package net.identio.server.utils;

public class MiscUtils {

    public static boolean equalsWithNulls(Object a, Object b) {

       return ((a == null) && (b == null)) || ((a != null) && a.equals(b));
    }
}
