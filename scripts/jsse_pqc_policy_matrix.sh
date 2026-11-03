#!/usr/bin/env bash
set -euo pipefail
umask 077

JDK="$HOME/.sdkman/candidates/java/25.0.5.0+8-tem"
JAVA="$JDK/bin/java"
JAVAC="$JDK/bin/javac"
KEYTOOL="$JDK/bin/keytool"

if [[ ! -x "$JAVA" ]]; then
  echo "ERROR: JDK_NOT_FOUND=$JDK"
  exit 1
fi

TEST="$(mktemp -d "$HOME/pqc-research/jsse-pqc-policy-20261103-XXXXXX")"

cat > "$TEST/JssePolicyProbe.java" <<'JAVA'
import javax.net.ssl.*;
import java.net.*;
import java.nio.file.*;
import java.io.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;

public final class JssePolicyProbe {
    static final String HYBRID = "X25519MLKEM768";

    static SSLContext context(Path file) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");

        try (InputStream in = Files.newInputStream(file)) {
            ks.load(in, "changeit".toCharArray());
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
            KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "changeit".toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);

        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        ctx.init(
            kmf.getKeyManagers(),
            tmf.getTrustManagers(),
            new SecureRandom());

        return ctx;
    }

    static void configure(SSLSocket socket, String groups) {
        socket.setEnabledProtocols(new String[]{"TLSv1.3"});
        SSLParameters p = socket.getSSLParameters();
        p.setNamedGroups(groups.split(","));
        socket.setSSLParameters(p);
    }

    static void configure(SSLServerSocket socket, String groups) {
        socket.setEnabledProtocols(new String[]{"TLSv1.3"});
        SSLParameters p = socket.getSSLParameters();
        p.setNamedGroups(groups.split(","));
        socket.setSSLParameters(p);
    }

    public static void main(String[] args) throws Exception {
        SSLContext ctx = context(Path.of(args[0]));

        if (args.length == 1) {
            String[] groups =
                ctx.getDefaultSSLParameters().getNamedGroups();

            boolean supported = groups != null &&
                Arrays.stream(groups).anyMatch(
                    x -> x.equalsIgnoreCase(HYBRID));

            System.out.println("JDK=" + Runtime.version());
            System.out.println("NAMED_GROUPS=" + Arrays.toString(groups));
            System.out.println("HYBRID_DEFAULT_SUPPORTED=" + supported);
            return;
        }

        ExecutorService executor =
            Executors.newSingleThreadExecutor();

        try (SSLServerSocket server =
                (SSLServerSocket) ctx.getServerSocketFactory()
                    .createServerSocket(
                        0, 1,
                        InetAddress.getByName("127.0.0.1"))) {

            server.setSoTimeout(12000);
            configure(server, args[2]);

            Future<String> result = executor.submit(() -> {
                try (SSLSocket accepted =
                        (SSLSocket) server.accept()) {

                    accepted.setSoTimeout(12000);
                    accepted.startHandshake();
                    return "PASS";

                } catch (Exception ex) {
                    return "FAIL:" +
                        ex.getClass().getSimpleName();
                }
            });

            String clientStatus = "PASS";

            try (SSLSocket client =
                    (SSLSocket) ctx.getSocketFactory()
                        .createSocket(
                            "127.0.0.1",
                            server.getLocalPort())) {

                client.setSoTimeout(12000);
                configure(client, args[1]);
                client.startHandshake();

                System.out.println(
                    "CLIENT_PROTOCOL=" +
                    client.getSession().getProtocol());

            } catch (Exception ex) {
                clientStatus =
                    "FAIL:" + ex.getClass().getSimpleName();
            }

            System.out.println("CLIENT_STATUS=" + clientStatus);
            System.out.println("SERVER_STATUS=" +
                result.get(14, TimeUnit.SECONDS));

        } finally {
            executor.shutdownNow();
        }
    }
}
JAVA

"$JAVAC" --release 21 \
    -d "$TEST" \
    "$TEST/JssePolicyProbe.java"

"$KEYTOOL" -genkeypair \
    -alias localhost \
    -keyalg EC \
    -groupname secp256r1 \
    -keystore "$TEST/local.p12" \
    -storetype PKCS12 \
    -storepass changeit \
    -keypass changeit \
    -dname "CN=localhost" \
    -ext SAN=dns:localhost,ip:127.0.0.1 \
    -validity 1 \
    -noprompt >/dev/null 2>&1

"$JAVA" -cp "$TEST" \
    JssePolicyProbe "$TEST/local.p12" \
    | tee "$TEST/environment.txt"

if ! grep -q "HYBRID_DEFAULT_SUPPORTED=true" \
    "$TEST/environment.txt"; then
    echo "RESULT=SKIPPED_PQC_TLS_UNAVAILABLE"
    echo "RESULT_DIR=$TEST"
    exit 0
fi

cat > "$TEST/cases.csv" <<'CSV'
case,client_groups,server_groups,policy
PQC_FIRST,X25519MLKEM768|x25519|secp256r1,X25519MLKEM768|x25519|secp256r1,OPPORTUNISTIC
CLASSICAL_FIRST,x25519|secp256r1|X25519MLKEM768,X25519MLKEM768|x25519|secp256r1,OPPORTUNISTIC
CLASSICAL_PEER_OPPORTUNISTIC,X25519MLKEM768|x25519|secp256r1,x25519|secp256r1,OPPORTUNISTIC
CLASSICAL_PEER_PQC_REQUIRED,X25519MLKEM768,x25519|secp256r1,PQC_REQUIRED
HYBRID_SERVER_PQC_REQUIRED,X25519MLKEM768,X25519MLKEM768|x25519|secp256r1,PQC_REQUIRED
HYBRID_SERVER_RETRY,x25519|secp256r1|X25519MLKEM768,X25519MLKEM768,PQC_REQUIRED
CSV

while IFS=, read -r name client server policy; do
    [[ "$name" == "case" ]] && continue

    client="${client//|/,}"
    server="${server//|/,}"

    echo "=== CASE=$name POLICY=$policy ==="

    timeout 40s "$JAVA" \
        -Djavax.net.debug=ssl:handshake \
        -cp "$TEST" \
        JssePolicyProbe \
        "$TEST/local.p12" \
        "$client" "$server" \
        > "$TEST/$name.log" 2>&1 || true

    grep -E \
        '^CLIENT_STATUS=|^SERVER_STATUS=|^CLIENT_PROTOCOL=' \
        "$TEST/$name.log" || true

done < "$TEST/cases.csv"

python3 - "$TEST" <<'PY'
import csv
import re
import sys
from pathlib import Path

base = Path(sys.argv[1])
results = []

with (base / "cases.csv").open() as f:
    cases = list(csv.DictReader(f))

for case in cases:
    name = case["case"]
    policy = case["policy"]
    log = (base / (name + ".log")).read_text(
        errors="replace")

    status = re.findall(
        r"^CLIENT_STATUS=(.*)$", log, re.M)

    success = bool(status and status[-1] == "PASS")

    groups = re.findall(
        r'"server_share"\s*:\s*\{\s*'
        r'"named group"\s*:\s*"?([A-Za-z0-9_-]+)',
        log, re.I)

    group = groups[-1] if groups else "UNKNOWN"

    if not success:
        verdict = (
            "REJECT"
            if policy == "PQC_REQUIRED"
            else "FAIL_OR_UNAVAILABLE"
        )
    elif group == "UNKNOWN":
        verdict = "INDETERMINATE"
    elif (policy == "PQC_REQUIRED" and
          group.lower() != "x25519mlkem768"):
        verdict = "VIOLATION"
    else:
        verdict = "PASS"

    results.append({
        "case": name,
        "policy": policy,
        "success": str(success).lower(),
        "selected_group": group,
        "verdict": verdict,
    })

    print(
        f"{name} POLICY={policy} "
        f"SUCCESS={str(success).lower()} "
        f"ACTUAL_GROUP={group} VERDICT={verdict}"
    )

with (base / "matrix.csv").open("w", newline="") as f:
    writer = csv.DictWriter(
        f, fieldnames=list(results[0]))
    writer.writeheader()
    writer.writerows(results)

print("EXPERIMENT_SCOPE=LOCAL_JSSE_REFERENCE")
print("UNKNOWN_GROUP_MEANS_INDETERMINATE")
print("RESULT_DIR=" + str(base))
PY

echo "GITHUB_UNCHANGED=true"
