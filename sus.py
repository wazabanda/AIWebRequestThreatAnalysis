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