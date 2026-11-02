import java.lang.reflect.*;
import java.util.Set;

public class Probe {
    public static void main(String[] args) throws Exception {
        Class<?> errorType = Class.forName(
            "br.unb.cic.mop.eh.ErrorType"
        );
        Class<?> description = Class.forName(
            "br.unb.cic.mop.eh.ErrorDescription"
        );
        Class<?> collectorClass = Class.forName(
            "br.unb.cic.mop.eh.ErrorCollector"
        );

        Object[] types = errorType.getEnumConstants();
        if (types == null || types.length == 0) {
            throw new IllegalStateException(
                "ErrorType enum unavailable"
            );
        }

        Object type = types[0];

        Constructor<?> constructor =
            description.getConstructor(
                errorType,
                String.class,
                String.class,
                String.class
            );

        Object first = constructor.newInstance(
            type,
            "Step159Spec",
            "example.Probe.method(Probe.java:1)",
            "expectation-A"
        );

        Object second = constructor.newInstance(
            type,
            "Step159Spec",
            "example.Probe.method(Probe.java:1)",
            "expectation-B"
        );

        System.out.println(
            "ERROR_OBJECTS_EQUAL: " +
            first.equals(second)
        );
        System.out.println(
            "HASHCODES_EQUAL: " +
            (first.hashCode() == second.hashCode())
        );

        Object collector = collectorClass
            .getMethod("instance").invoke(null);

        Method add = collectorClass.getMethod(
            "addError", description
        );

        Method getErrors = collectorClass.getMethod(
            "getErrors"
        );

        add.invoke(collector, first);
        add.invoke(collector, second);

        int count = ((Set<?>)getErrors.invoke(
            collector
        )).size();

        System.out.println(
            "SET_SIZE_AFTER_TWO_ERRORS: " + count
        );

        if (count != 1) {
            throw new IllegalStateException(
                "Unexpected deduplication result"
            );
        }

        if (args.length > 0 &&
            args[0].equals("reset")) {

            collectorClass.getMethod(
                "reset"
            ).invoke(collector);

            add.invoke(collector, first);

            System.out.println(
                "SET_SIZE_AFTER_RESET: " +
                ((Set<?>)getErrors.invoke(
                    collector
                )).size()
            );
        }
    }
}
