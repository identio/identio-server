package net.identio.server.utils;

public class MiscUtils {

    public static boolean equalsWithNulls(Object a, Object b) {
        if (a == b) return true;
        if ((a == null) || (b == null)) return false;
        return a.equals(b);
    }
}
