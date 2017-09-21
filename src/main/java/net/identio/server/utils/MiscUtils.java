package net.identio.server.utils;

public class MiscUtils {

    public static boolean equalsWithNulls(Object a, Object b) {
        if (a == b) return true;
        return (a != null) && (b != null) && a.equals(b);
    }
}
