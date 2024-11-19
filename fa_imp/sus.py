badwords = [
    "select", "insert", "update", "delete", "union", "drop", "eval", "exec", "base64_decode", 
    "system", "shell", "phpinfo", "alert", "document.cookie", "exec", "os.system", "os.popen"
]

symbols = ["'", '"', '--', '{', '}', ' ', '%', ';', '<', '>']

feature_columns = [
    'path_single_q', 'path_double_q', 'path_dashes', 'path_braces', 'path_spaces', 
    'path_percentages', 'path_semicolons', 'path_angle_brackets', 'path_special_chars', 
    'path_badwords_count', 'body_single_q', 'body_double_q', 'body_dashes', 'body_braces', 
    'body_spaces', 'body_percentages', 'body_semicolons', 'body_angle_brackets', 
    'body_special_chars', 'body_badwords_count', 'path_length', 'body_length'
]



# Define the list of bad words
bad_words = [
    "select", "from", "where", "insert", "into", "values", "' or", "update", "set", "delete", "drop",
    "table", "database", "schema", "union", "all", "concat", "group_concat", "column_name",
    "information_schema", "sys.schemas", "user()", "current_user()", "session_user()",
    "system_user()", "database()", "version()", "@@version", "@@datadir", "@@basedir",
    "eval", "exec", "execute", "call", "proc", "procedure", "shell", "system", "os.system",
    "os.popen", "popen", "pcntl_exec", "assert", "passthru", "dl", "opendir", "readdir",
    "mkdir", "rmdir", "unlink", "chmod", "chown", "symlink", "link", "uname", "whoami",
    "getenv", "putenv", "gethost", "gethostbyname", "dns_get_record", "dns_get_mx",
    "php_uname", "phpinfo", "phpversion", "highlight_file", "show_source", "config_path",
    "document.cookie", "document.write", "window.location", "window.navigator.userAgent",
    "location.href", "location.host", "location.pathname", "location.protocol", "alert",
    "prompt", "confirm", "iframe", "script", ".img", ".svg", "base64_decode", "base64_encode",
    "hex2bin", "bin2hex", "urldecode", "urlencode", "rawurldecode", "rawurlencode",
    "md5", "sha1", "sha256", "sha384", "sha512", "crc32", "crypt", "getimagesizefromstring",
    "exif_read_data", "exif_thumbnail", "exif_imagetype", "gd_info", "getimagesize",
    "getimagesizefromstring", "imagecreatefromstring", "parse_url", "parse_str",
    "http_build_query", "getallheaders", "apache_request_headers", "get_headers",
    "get_included_files", "get_loaded_extensions", "get_defined_constants",
    "get_defined_functions", "get_declared_classes", "get_declared_interfaces",
    "get_declared_traits", "get_class_methods", "get_class_vars", "get_class_props",
    "get_object_vars", "get_parent_class", "class_exists", "interface_exists",
    "trait_exists", "method_exists", "property_exists", "is_subclass_of", "is_a",
    "get_called_class", "get_class", "get_this_class", "get_class_this",
    "get_class_intro", "get_class_methods", "get_class_vars", "get_class_props"
]