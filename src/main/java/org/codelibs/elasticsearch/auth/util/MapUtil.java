package org.codelibs.elasticsearch.auth.util;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class MapUtil {
    public static final String DATE_TIME_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSS";

    private MapUtil() {
    }

    public static String[] getAsArray(final Map<String, Object> map,
            final String key, final String[] defaultValue) {
        final Object obj = map.get(key);
        if (obj instanceof String) {
            return new String[] { obj.toString() };
        } else if (obj instanceof String[]) {
            return (String[]) obj;
        } else if (obj instanceof List) {
            @SuppressWarnings("unchecked")
            final List<String> list = (List<String>) obj;
            return list.toArray(new String[list.size()]);
        }
        return defaultValue;
    }

    public static String getAsString(final Map<String, Object> map,
            final String key, final String defaultValue) {
        final Object obj = map.get(key);
        if (obj instanceof String) {
            return obj.toString();
        } else if (obj instanceof String[]) {
            return ((String[]) obj)[0];
        } else if (obj instanceof List) {
            @SuppressWarnings("unchecked")
            final List<String> list = (List<String>) obj;
            return list.get(0);
        }
        return defaultValue;
    }

    @SuppressWarnings("unchecked")
    public static List<String> getAsList(final Map<String, Object> map,
            final String key, final List<String> defaultValue) {
        final Object obj = map.get(key);
        if (obj instanceof String) {
            final List<String> list = new ArrayList<String>();
            list.add(obj.toString());
            return list;
        } else if (obj instanceof String[]) {
            final List<String> list = new ArrayList<String>();
            list.add(obj.toString());
            for (final String value : (String[]) obj) {
                list.add(value);
            }
            return list;
        } else if (obj instanceof List) {
            return (List<String>) obj;
        }
        return defaultValue;
    }

    public static Date getAsDate(final Map<String, Object> map,
            final String key, final Date defaultValue) {
        final Object obj = map.get(key);
        if (obj instanceof String) {
            final SimpleDateFormat sdf = new SimpleDateFormat(DATE_TIME_FORMAT,
                    Locale.ROOT);
            try {
                return sdf.parse(obj.toString());
            } catch (final ParseException e) {
                return defaultValue;
            }
        } else if (obj instanceof Date) {
            return (Date) obj;
        }
        return defaultValue;
    }
}
