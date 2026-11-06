#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
sha256sum -c dependencies.sha256
mkdir -p build
java -m jdk.compiler/com.sun.tools.javac.Main --release 17 -Xlint:all -Werror -cp lib/bcprov-jdk18on-1.86.jar -d build PolicyComparison.java PqcExtension.java NonceReservations.java StabilityTest.java PartBenchmark.java EndToEndBenchmark.java TrustedStateStore.java RecoveryTest.java RecoveryBenchmark.java EvidenceMatrix.java SecretBuffer.java SecurityAuditTest.java LifecycleCleanupTest.java PacketCodecBenchmark.java CodecRegressionTest.java AnchorCodec.java AnchorCodecBenchmark.java CryptoCli.java CheckpointCodec.java OptimizationCheck.java ReuseCleanupTest.java ReopenCost.java SmallCheckpointCost.java PacketFileOutputTest.java ParallelBatchTest.java ParallelBatchBenchmark.java ParallelRiskTest.java ParallelRiskBenchmark.java ParallelFollowupTest.java
java -Xms256m -Xmx512m -cp 'build:lib/bcprov-jdk18on-1.86.jar' StabilityTest results/integrated
for fork in 1 2 3; do
  java -Xms256m -Xmx512m -cp 'build:lib/bcprov-jdk18on-1.86.jar' EndToEndBenchmark "results/request/fork-$fork" "$((fork-1))"
  java -Xms256m -Xmx512m -cp 'build:lib/bcprov-jdk18on-1.86.jar' PartBenchmark "results/parts/fork-$fork" "$((fork-1))"
  java -Xms256m -Xmx512m -cp 'build:lib/bcprov-jdk18on-1.86.jar' PolicyComparison "results/classical/fork-$fork" "$((fork-1))"
  java -Xms256m -Xmx512m -cp 'build:lib/bcprov-jdk18on-1.86.jar' PqcExtension "results/pqc/fork-$fork" "$((fork-1))"
  java -Xmx512m -cp 'build:lib/bcprov-jdk18on-1.86.jar' RecoveryBenchmark "results/persistent/fork-$fork" "$((fork-1))"
done

python3 process-check.py
java -Xmx512m -cp 'build:lib/bcprov-jdk18on-1.86.jar' RecoveryTest results/recovery
python3 engine-process-check.py

# Balanced P3-first/P5-first request experiments: six fresh JVMs.
for fork in 4 5 6; do
  java -Xms256m -Xmx512m -cp 'build:lib/bcprov-jdk18on-1.86.jar' EndToEndBenchmark "results/request/fork-$fork" "$((fork-1))"
  java -Xmx512m -cp 'build:lib/bcprov-jdk18on-1.86.jar' RecoveryBenchmark "results/persistent/fork-$fork" "$((fork-1))"
done
for fork in 1 2 3 4 5 6; do
  java -Xmx512m -cp 'build:lib/bcprov-jdk18on-1.86.jar' EvidenceMatrix "results/evidence/fork-$fork" "$((fork-1))"
done

java -Xmx512m -cp 'build:lib/bcprov-jdk18on-1.86.jar' SecurityAuditTest results/security

java -cp 'build:lib/bcprov-jdk18on-1.86.jar' LifecycleCleanupTest results/security

for fork in 1 2 3; do
  java -Xms256m -Xmx512m -cp 'build:lib/bcprov-jdk18on-1.86.jar' PacketCodecBenchmark "results/codec/fork-$fork" "$((fork-1))"
done

java -Xmx512m -cp 'build:lib/bcprov-jdk18on-1.86.jar' CodecRegressionTest results/security

for fork in 1 2 3; do
  java -Xms256m -Xmx512m -cp 'build:lib/bcprov-jdk18on-1.86.jar' AnchorCodecBenchmark "results/anchor/fork-$fork" "$((fork-1))"
done

python3 cli-check.py

python3 cli-wrapper-check.py
python3 cli-build-check.py
python3 cli-cache-check.py
python3 cli-integrity-check.py

python3 easy-check.py

for fork in 1 2 3; do
  java -Xms256m -Xmx512m -cp build:lib/bcprov-jdk18on-1.86.jar OptimizationCheck "results/optimization/fork-$fork" "$fork"
done
python3 optimization-summary.py
python3 easy-optimization-check.py
python3 normal-v13-compatibility.py
python3 normal-v14-compatibility.py
java -Xmx512m -cp build:lib/bcprov-jdk18on-1.86.jar ReuseCleanupTest results/security
python3 easy-batch-check.py
java -m jdk.compiler/com.sun.tools.javac.Main --release 17 -Xlint:all -Werror -cp build -d build StoreIsolationTest.java
java -cp build StoreIsolationTest results/security
python3 reuse-measure.py
python3 batch-measure.py

for fork in 1 2 3; do
  java -Xms256m -Xmx512m -cp build:lib/bcprov-jdk18on-1.86.jar PacketFileOutputTest "results/file-output/fork-$fork" "$fork"
done
python3 file-output-summary.py
java -Xmx512m -cp build:lib/bcprov-jdk18on-1.86.jar ParallelBatchTest results/security
python3 easy-parallel-check.py
java -Xmx512m -cp build:lib/bcprov-jdk18on-1.86.jar ParallelRiskTest results/security
python3 easy-stream-check.py
python3 packet-stream-check.py
python3 packet-stream-roundtrip.py
python3 decrypt-memory-check.py
python3 decrypt-auth-check.py
java -Xmx512m -cp build:lib/bcprov-jdk18on-1.86.jar ParallelFollowupTest results/security
python3 easy-cancel-check.py
python3 parallel-measure.py
python3 parallel-risk-measure.py

python3 paper.py run
python3 paper-check.py
