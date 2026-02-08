###############################################################################
#	Filename:	UKConfig.py
#	
#	Confidential and Proprietary, Copyright 2002 by Totally Games
#	
#	Maps US scancodes to Unicode
#	
#	Created:	1/18/02 -	Colin Carley
###############################################################################

import App

def MapScancodes():
	pDatabase = App.g_kLocalizationManager.Load("data/TGL/Keyboard Mapping.tgl")

	# If pDatabase fails to load, it will manage by creating a string from the
	# input character.
	
	### NORMAL STATE ###

	# Map top row (Esc, function keys, printscreen, scrolllock, pause)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ESCAPE, App.KY_ESCAPE, pDatabase, "ESC")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_F1, App.KY_F1, pDatabase, "F1")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_F2, App.KY_F2, pDatabase, "F2")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_F3, App.KY_F3, pDatabase, "F3")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_F4, App.KY_F4, pDatabase, "F4")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_F5, App.KY_F5, pDatabase, "F5")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_F6, App.KY_F6, pDatabase, "F6")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_F7, App.KY_F7, pDatabase, "F7")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_F8, App.KY_F8, pDatabase, "F8")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_F9, App.KY_F9, pDatabase, "F9")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_F10, App.KY_F10, pDatabase, "F10")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_F11, App.KY_F11, pDatabase, "F11")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_F12, App.KY_F12, pDatabase, "F12")

	# Map the first row
	App.g_kInputManager.RegisterUnicodeKey(App.WC_BACKQUOTE, App.KY_BACKQUOTE, pDatabase, "`")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_1, App.KY_1, pDatabase, "1")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_2, App.KY_2, pDatabase, "2")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_3, App.KY_3, pDatabase, "3")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_4, App.KY_4, pDatabase, "4")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_5, App.KY_5, pDatabase, "5")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_6, App.KY_6, pDatabase, "6")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_7, App.KY_7, pDatabase, "7")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_8, App.KY_8, pDatabase, "8")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_9, App.KY_9, pDatabase, "9")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_0, App.KY_0, pDatabase, "0")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_MINUS, App.KY_MINUS, pDatabase, "-")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_EQUALS, App.KY_EQUALS, pDatabase, "=")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_BACKSPACE, App.KY_BACKSPACE, pDatabase, "BACKSP")

	# Map the second row
	App.g_kInputManager.RegisterUnicodeKey(App.WC_TAB, App.KY_TAB, pDatabase, "TAB")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_Q, App.KY_Q, pDatabase, "q")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_W, App.KY_W, pDatabase, "w")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_E, App.KY_E, pDatabase, "e")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_R, App.KY_R, pDatabase, "r")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_T, App.KY_T, pDatabase, "t")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_Y, App.KY_Y, pDatabase, "y")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_U, App.KY_U, pDatabase, "u")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_I, App.KY_I, pDatabase, "i")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_O, App.KY_O, pDatabase, "o")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_P, App.KY_P, pDatabase, "p")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_OPEN_BRACKET, App.KY_OPEN_BRACKET, pDatabase, "[")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CLOSE_BRACKET, App.KY_CLOSE_BRACKET, pDatabase, "]")

	# Map third row
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CAPSLOCK, App.KY_CAPSLOCK, pDatabase, "CAPS")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_A, App.KY_A, pDatabase, "a")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_S, App.KY_S, pDatabase, "s")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_D, App.KY_D, pDatabase, "d")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_F, App.KY_F, pDatabase, "f")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_G, App.KY_G, pDatabase, "g")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_H, App.KY_H, pDatabase, "h")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_J, App.KY_J, pDatabase, "j")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_K, App.KY_K, pDatabase, "k")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_L, App.KY_L, pDatabase, "l")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_SEMICOLON, App.KY_SEMICOLON, pDatabase, ";")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_QUOTE, App.KY_QUOTE, pDatabase, "'")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMBER_SIGN, App.KY_EU_RIGHT, pDatabase, "#")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_RETURN, App.KY_RETURN, pDatabase, "ENTER")

	# Map fourth row
	App.g_kInputManager.RegisterUnicodeKey(App.WC_SHIFT, App.KY_SHIFT, pDatabase, "SHIFT")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_BACKSLASH, App.KY_EU_LEFT, pDatabase, "\\")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_Z, App.KY_Z, pDatabase, "z")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_X, App.KY_X, pDatabase, "x")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_C, App.KY_C, pDatabase, "c")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_V, App.KY_V, pDatabase, "v")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_B, App.KY_B, pDatabase, "b")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_N, App.KY_N, pDatabase, "n")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_M, App.KY_M, pDatabase, "m")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_COMMA, App.KY_COMMA, pDatabase, ",")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_PERIOD, App.KY_PERIOD, pDatabase, ".")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_SLASH, App.KY_SLASH, pDatabase, "/")

	# Map fifth row
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL, App.KY_CTRL, pDatabase, "CTRL")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT, App.KY_ALT, pDatabase, "ALT")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_SPACE, App.KY_SPACE, pDatabase, "SPACE")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALTGR, App.KY_ALTGR, pDatabase, "ALTGR")

	# Map middle column (Top, 1st, 2nd, 4th, 5th)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_PRINTSCREEN, App.KY_PRINTSCREEN, pDatabase, "PRINT SCRN")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_SCROLL, App.KY_SCROLL, pDatabase, "SCRL LOCK")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_PAUSE, App.KY_PAUSE, pDatabase, "PAUSE")

	App.g_kInputManager.RegisterUnicodeKey(App.WC_INSERT, App.KY_INSERT, pDatabase, "INS")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_HOME, App.KY_HOME, pDatabase, "HOME")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_PAGEUP, App.KY_PAGEUP, pDatabase, "PG UP")

	App.g_kInputManager.RegisterUnicodeKey(App.WC_DELETE, App.KY_DELETE, pDatabase, "DEL")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_END, App.KY_END, pDatabase, "END")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_PAGEDOWN, App.KY_PAGEDOWN, pDatabase, "PG DN")

	App.g_kInputManager.RegisterUnicodeKey(App.WC_UP, App.KY_UP, pDatabase, "UP")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_DOWN, App.KY_DOWN, pDatabase, "DOWN")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_LEFT, App.KY_LEFT, pDatabase, "LEFT")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_RIGHT, App.KY_RIGHT, pDatabase, "RIGHT")

	# Map Numkeys
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMLOCK, App.KY_NUMLOCK, pDatabase, "NUM LOCK")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_DIVIDE, App.KY_DIVIDE, pDatabase, "Num /")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_MULTIPLY, App.KY_MULTIPLY, pDatabase, "Num *")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_SUBTRACT, App.KY_SUBTRACT, pDatabase, "Num -")

	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD7, App.KY_NUMPAD7, pDatabase, "Num 7")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD8, App.KY_NUMPAD8, pDatabase, "Num 8")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD9, App.KY_NUMPAD9, pDatabase, "Num 9")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ADD, App.KY_ADD, pDatabase, "Num +")

	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD4, App.KY_NUMPAD4, pDatabase, "Num 4")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD5, App.KY_NUMPAD5, pDatabase, "Num 5")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD6, App.KY_NUMPAD6, pDatabase, "Num 6")

	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD1, App.KY_NUMPAD1, pDatabase, "Num 1")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD2, App.KY_NUMPAD2, pDatabase, "Num 2")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD3, App.KY_NUMPAD3, pDatabase, "Num 3")

	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD0, App.KY_NUMPAD0, pDatabase, "Num 0")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_DECIMAL, App.KY_DECIMAL, pDatabase, "Num .")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPADENTER, App.KY_NUMPADENTER, pDatabase, "Num Enter")


	### SHIFT STATE ###
	# Map top row, Shifted (Esc, function keys, printscreen, scrolllock, pause)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ESCAPE, App.KY_ESCAPE, pDatabase, "ESC", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_F1, App.KY_F1, pDatabase, "F1", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_F2, App.KY_F2, pDatabase, "F2", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_F3, App.KY_F3, pDatabase, "F3", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_F4, App.KY_F4, pDatabase, "F4", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_F5, App.KY_F5, pDatabase, "F5", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_F6, App.KY_F6, pDatabase, "F6", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_F7, App.KY_F7, pDatabase, "F7", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_F8, App.KY_F8, pDatabase, "F8", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_F9, App.KY_F9, pDatabase, "F9", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_F10, App.KY_F10, pDatabase, "F10", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_F11, App.KY_F11, pDatabase, "F11", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_F12, App.KY_F12, pDatabase, "F12", App.KY_SHIFT)

	# Map first row, Shifted
	#App.g_kInputManager.RegisterUnicodeKey(App.WC_BRACKET, App.KY_BACKQUOTE, pDatabase, "Bracket", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_EXCLAMATION, App.KY_1, pDatabase, "!", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_DOUBLE_QUOTE, App.KY_2, pDatabase, "\"", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_POUND_SIGN, App.KY_3, pDatabase, "POUND", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_DOLLAR_SIGN, App.KY_4, pDatabase, "$", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_PERCENT, App.KY_5, pDatabase, "%", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CARRET, App.KY_6, pDatabase, "^", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_AMPERSAND, App.KY_7, pDatabase, "&", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ASTERISK, App.KY_8, pDatabase, "*", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_OPEN_PAREN, App.KY_9, pDatabase, "(", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CLOSE_PAREN, App.KY_0, pDatabase, ")", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_UNDERSCORE, App.KY_MINUS, pDatabase, "_", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_PLUS, App.KY_EQUALS, pDatabase, "+", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_BACKSPACE, App.KY_BACKSPACE, pDatabase, "BACKSP", App.KY_SHIFT)

	# Map second row, Shifted
	App.g_kInputManager.RegisterUnicodeKey(App.WC_TAB, App.KY_TAB, pDatabase, "TAB", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CAPS_Q, App.KY_Q, pDatabase, "Q", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CAPS_W, App.KY_W, pDatabase, "W", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CAPS_E, App.KY_E, pDatabase, "E", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CAPS_R, App.KY_R, pDatabase, "R", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CAPS_T, App.KY_T, pDatabase, "T", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CAPS_Y, App.KY_Y, pDatabase, "Y", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CAPS_U, App.KY_U, pDatabase, "U", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CAPS_I, App.KY_I, pDatabase, "I", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CAPS_O, App.KY_O, pDatabase, "O", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CAPS_P, App.KY_P, pDatabase, "P", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CURLY_BRACE_OPEN, App.KY_OPEN_BRACKET, pDatabase, "{", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CURLY_BRACE_CLOSE, App.KY_CLOSE_BRACKET, pDatabase, "}", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_SEPARATOR, App.KY_SEPARATOR, pDatabase, "|", App.KY_SHIFT)

	# Map third row, Shifted
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CAPSLOCK, App.KY_CAPSLOCK, pDatabase, "CAPS", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CAPS_A, App.KY_A, pDatabase, "A", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CAPS_S, App.KY_S, pDatabase, "S", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CAPS_D, App.KY_D, pDatabase, "D", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CAPS_F, App.KY_F, pDatabase, "F", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CAPS_G, App.KY_G, pDatabase, "G", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CAPS_H, App.KY_H, pDatabase, "H", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CAPS_J, App.KY_J, pDatabase, "J", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CAPS_K, App.KY_K, pDatabase, "K", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CAPS_L, App.KY_L, pDatabase, "L", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_COLON, App.KY_SEMICOLON, pDatabase, ":", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_AT_SIGN, App.KY_QUOTE, pDatabase, "@", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_TILDE, App.KY_EU_RIGHT, pDatabase, "~", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_RETURN, App.KY_RETURN, pDatabase, "ENTER", App.KY_SHIFT)

	# Map fourth row, Shifted
	App.g_kInputManager.RegisterUnicodeKey(App.WC_SHIFT, App.KY_SHIFT, pDatabase, "SHIFT", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_SEPARATOR, App.KY_EU_LEFT, pDatabase, "|", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CAPS_Z, App.KY_Z, pDatabase, "Z", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CAPS_X, App.KY_X, pDatabase, "X", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CAPS_C, App.KY_C, pDatabase, "C", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CAPS_V, App.KY_V, pDatabase, "V", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CAPS_B, App.KY_B, pDatabase, "B", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CAPS_N, App.KY_N, pDatabase, "N", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CAPS_M, App.KY_M, pDatabase, "M", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_LESS_THAN, App.KY_COMMA, pDatabase, "<", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_GREATER_THAN, App.KY_PERIOD, pDatabase, ">", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_QUESTION, App.KY_SLASH, pDatabase, "?", App.KY_SHIFT)

	# Map fifth row, Shifted
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL, App.KY_CTRL, pDatabase, "CTRL", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT, App.KY_ALT, pDatabase, "ALT", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_SPACE, App.KY_SPACE, pDatabase, "SPACE", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALTGR, App.KY_ALTGR, pDatabase, "ALTGR", App.KY_SHIFT)

	# Map middle column (Top, 1st, 2nd, 4th, 5th)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_PRINTSCREEN, App.KY_PRINTSCREEN, pDatabase, "PRINT SCRN", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_PAUSE, App.KY_PAUSE, pDatabase, "PAUSE", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_SCROLL, App.KY_SCROLL, pDatabase, "SCRL LOCK", App.KY_SHIFT)

	App.g_kInputManager.RegisterUnicodeKey(App.WC_INSERT, App.KY_INSERT, pDatabase, "INS", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_HOME, App.KY_HOME, pDatabase, "HOME", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_PAGEUP, App.KY_PAGEUP, pDatabase, "PG UP", App.KY_SHIFT)

	App.g_kInputManager.RegisterUnicodeKey(App.WC_DELETE, App.KY_DELETE, pDatabase, "DEL", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_END, App.KY_END, pDatabase, "END", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_PAGEDOWN, App.KY_PAGEDOWN, pDatabase, "PG DN", App.KY_SHIFT)

	App.g_kInputManager.RegisterUnicodeKey(App.WC_UP, App.KY_UP, pDatabase, "UP", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_DOWN, App.KY_DOWN, pDatabase, "DOWN", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_LEFT, App.KY_LEFT, pDatabase, "LEFT", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_RIGHT, App.KY_RIGHT, pDatabase, "RIGHT", App.KY_SHIFT)

	# Map Numkeys
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMLOCK, App.KY_NUMLOCK, pDatabase, "NUM LOCK", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_DIVIDE, App.KY_DIVIDE, pDatabase, "Num /", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_MULTIPLY, App.KY_MULTIPLY, pDatabase, "Num *", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_SUBTRACT, App.KY_SUBTRACT, pDatabase, "Num -", App.KY_SHIFT)

	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD7, App.KY_NUMPAD7, pDatabase, "Num 7", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD8, App.KY_NUMPAD8, pDatabase, "Num 8", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD9, App.KY_NUMPAD9, pDatabase, "Num 9", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ADD, App.KY_ADD, pDatabase, "Num +", App.KY_SHIFT)

	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD4, App.KY_NUMPAD4, pDatabase, "Num 4", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD5, App.KY_NUMPAD5, pDatabase, "Num 5", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD6, App.KY_NUMPAD6, pDatabase, "Num 6", App.KY_SHIFT)

	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD1, App.KY_NUMPAD1, pDatabase, "Num 1", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD2, App.KY_NUMPAD2, pDatabase, "Num 2", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD3, App.KY_NUMPAD3, pDatabase, "Num 3", App.KY_SHIFT)

	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD0, App.KY_NUMPAD0, pDatabase, "Num 0", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_DECIMAL, App.KY_DECIMAL, pDatabase, "Num .", App.KY_SHIFT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPADENTER, App.KY_NUMPADENTER, pDatabase, "Num Enter", App.KY_SHIFT)


	### ALT STATE ###
	# Map top row (Esc, function keys, printscreen, scrolllock, pause)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ESCAPE, App.KY_ESCAPE, pDatabase, "ESC", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_F1, App.KY_F1, pDatabase, "ALT-F1", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_F2, App.KY_F2, pDatabase, "ALT-F2", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_F3, App.KY_F3, pDatabase, "ALT-F3", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_F4, App.KY_F4, pDatabase, "ALT-F4", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_F5, App.KY_F5, pDatabase, "ALT-F5", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_F6, App.KY_F6, pDatabase, "ALT-F6", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_F7, App.KY_F7, pDatabase, "ALT-F7", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_F8, App.KY_F8, pDatabase, "ALT-F8", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_F9, App.KY_F9, pDatabase, "ALT-F9", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_F10, App.KY_F10, pDatabase, "ALT-F10", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_F11, App.KY_F11, pDatabase, "ALT-F11", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_F12, App.KY_F12, pDatabase, "ALT-F12", App.KY_ALT)

	# Map the first row
	App.g_kInputManager.RegisterUnicodeKey(App.WC_BACKQUOTE, App.KY_BACKQUOTE, pDatabase, "`", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_1, App.KY_1, pDatabase, "ALT-1", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_2, App.KY_2, pDatabase, "ALT-2", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_3, App.KY_3, pDatabase, "ALT-3", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_4, App.KY_4, pDatabase, "ALT-4", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_5, App.KY_5, pDatabase, "ALT-5", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_6, App.KY_6, pDatabase, "ALT-6", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_7, App.KY_7, pDatabase, "ALT-7", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_8, App.KY_8, pDatabase, "ALT-8", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_9, App.KY_9, pDatabase, "ALT-9", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_0, App.KY_0, pDatabase, "ALT-0", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_MINUS, App.KY_MINUS, pDatabase, "-", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_EQUALS, App.KY_EQUALS, pDatabase, "=", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_BACKSPACE, App.KY_BACKSPACE, pDatabase, "BACKSP", App.KY_ALT)

	# Map the second row
	App.g_kInputManager.RegisterUnicodeKey(App.WC_TAB, App.KY_TAB, pDatabase, "TAB", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_Q, App.KY_Q, pDatabase, "ALT-Q", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_W, App.KY_W, pDatabase, "ALT-W", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_E, App.KY_E, pDatabase, "ALT-E", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_R, App.KY_R, pDatabase, "ALT-R", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_T, App.KY_T, pDatabase, "ALT-T", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_Y, App.KY_Y, pDatabase, "ALT-Y", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_U, App.KY_U, pDatabase, "ALT-U", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_I, App.KY_I, pDatabase, "ALT-I", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_O, App.KY_O, pDatabase, "ALT-O", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_P, App.KY_P, pDatabase, "ALT-P", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_OPEN_BRACKET, App.KY_OPEN_BRACKET, pDatabase, "[", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CLOSE_BRACKET, App.KY_CLOSE_BRACKET, pDatabase, "]", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_BACKSLASH, App.KY_SEPARATOR, pDatabase, "\\", App.KY_ALT)

	# Map third row
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CAPSLOCK, App.KY_CAPSLOCK, pDatabase, "CAPS", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_A, App.KY_A, pDatabase, "ALT-A", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_S, App.KY_S, pDatabase, "ALT-S", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_D, App.KY_D, pDatabase, "ALT-D", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_F, App.KY_F, pDatabase, "ALT-F", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_G, App.KY_G, pDatabase, "ALT-G", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_H, App.KY_H, pDatabase, "ALT-H", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_J, App.KY_J, pDatabase, "ALT-J", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_K, App.KY_K, pDatabase, "ALT-K", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_L, App.KY_L, pDatabase, "ALT-L", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_SEMICOLON, App.KY_SEMICOLON, pDatabase, ";", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_QUOTE, App.KY_QUOTE, pDatabase, "'", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_RETURN, App.KY_RETURN, pDatabase, "ENTER", App.KY_ALT)

	# Map fourth row
	App.g_kInputManager.RegisterUnicodeKey(App.WC_SHIFT, App.KY_SHIFT, pDatabase, "SHIFT", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_Z, App.KY_Z, pDatabase, "ALT-Z", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_X, App.KY_X, pDatabase, "ALT-X", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_C, App.KY_C, pDatabase, "ALT-C", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_V, App.KY_V, pDatabase, "ALT-V", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_B, App.KY_B, pDatabase, "ALT-B", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_N, App.KY_N, pDatabase, "ALT-N", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_M, App.KY_M, pDatabase, "ALT-M", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_COMMA, App.KY_COMMA, pDatabase, ",", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_PERIOD, App.KY_PERIOD, pDatabase, ".", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_SLASH, App.KY_SLASH, pDatabase, "/", App.KY_ALT)

	# Map fifth row
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL, App.KY_CTRL, pDatabase, "CTRL", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT, App.KY_ALT, pDatabase, "ALT", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_SPACE, App.KY_SPACE, pDatabase, "SPACE", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALTGR, App.KY_ALTGR, pDatabase, "ALTGR", App.KY_ALT)

	# Map middle column (Top, 1st, 2nd, 4th, 5th)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_PRINTSCREEN, App.KY_PRINTSCREEN, pDatabase, "PRINT SCRN", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_PAUSE, App.KY_PAUSE, pDatabase, "PAUSE", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_SCROLL, App.KY_SCROLL, pDatabase, "SCRL LOCK", App.KY_ALT)

	App.g_kInputManager.RegisterUnicodeKey(App.WC_INSERT, App.KY_INSERT, pDatabase, "INS", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_HOME, App.KY_HOME, pDatabase, "HOME", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_PAGEUP, App.KY_PAGEUP, pDatabase, "PG UP", App.KY_ALT)

	App.g_kInputManager.RegisterUnicodeKey(App.WC_DELETE, App.KY_DELETE, pDatabase, "DEL", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_END, App.KY_END, pDatabase, "END", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_PAGEDOWN, App.KY_PAGEDOWN, pDatabase, "PG DN", App.KY_ALT)

	App.g_kInputManager.RegisterUnicodeKey(App.WC_UP, App.KY_UP, pDatabase, "UP", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_DOWN, App.KY_DOWN, pDatabase, "DOWN", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_LEFT, App.KY_LEFT, pDatabase, "LEFT", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_RIGHT, App.KY_RIGHT, pDatabase, "RIGHT", App.KY_ALT)

	# Map Numkeys
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMLOCK, App.KY_NUMLOCK, pDatabase, "NUM LOCK", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_DIVIDE, App.KY_DIVIDE, pDatabase, "Num /", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_MULTIPLY, App.KY_MULTIPLY, pDatabase, "Num *", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_SUBTRACT, App.KY_SUBTRACT, pDatabase, "Num -", App.KY_ALT)

	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD7, App.KY_NUMPAD7, pDatabase, "Num 7", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD8, App.KY_NUMPAD8, pDatabase, "Num 8", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD9, App.KY_NUMPAD9, pDatabase, "Num 9", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ADD, App.KY_ADD, pDatabase, "Num +", App.KY_ALT)

	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD4, App.KY_NUMPAD4, pDatabase, "Num 4", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD5, App.KY_NUMPAD5, pDatabase, "Num 5", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD6, App.KY_NUMPAD6, pDatabase, "Num 6", App.KY_ALT)

	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD1, App.KY_NUMPAD1, pDatabase, "Num 1", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD2, App.KY_NUMPAD2, pDatabase, "Num 2", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD3, App.KY_NUMPAD3, pDatabase, "Num 3", App.KY_ALT)

	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD0, App.KY_NUMPAD0, pDatabase, "Num 0", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_DECIMAL, App.KY_DECIMAL, pDatabase, "Num .", App.KY_ALT)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPADENTER, App.KY_NUMPADENTER, pDatabase, "Num Enter", App.KY_ALT)


	### CTRL STATE ###

	# Map top row (Esc, function keys, printscreen, scrolllock, pause)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ESCAPE, App.KY_ESCAPE, pDatabase, "ESC", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_F1, App.KY_F1, pDatabase, "F1", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_F2, App.KY_F2, pDatabase, "F2", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_F3, App.KY_F3, pDatabase, "F3", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_F4, App.KY_F4, pDatabase, "F4", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_F5, App.KY_F5, pDatabase, "F5", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_F6, App.KY_F6, pDatabase, "F6", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_F7, App.KY_F7, pDatabase, "F7", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_F8, App.KY_F8, pDatabase, "F8", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_F9, App.KY_F9, pDatabase, "F9", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_F10, App.KY_F10, pDatabase, "F10", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_F11, App.KY_F11, pDatabase, "F11", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_F12, App.KY_F12, pDatabase, "F12", App.KY_CTRL)

	# Map the first row
	App.g_kInputManager.RegisterUnicodeKey(App.WC_BACKQUOTE, App.KY_BACKQUOTE, pDatabase, "`", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_1, App.KY_1, pDatabase, "1", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_2, App.KY_2, pDatabase, "2", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_3, App.KY_3, pDatabase, "3", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_4, App.KY_4, pDatabase, "4", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_5, App.KY_5, pDatabase, "5", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_6, App.KY_6, pDatabase, "6", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_7, App.KY_7, pDatabase, "7", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_8, App.KY_8, pDatabase, "8", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_9, App.KY_9, pDatabase, "9", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_0, App.KY_0, pDatabase, "0", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_MINUS, App.KY_MINUS, pDatabase, "-", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_EQUALS, App.KY_EQUALS, pDatabase, "=", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_BACKSPACE, App.KY_BACKSPACE, pDatabase, "BACKSP", App.KY_CTRL)

	# Map the second row
	App.g_kInputManager.RegisterUnicodeKey(App.WC_TAB, App.KY_TAB, pDatabase, "TAB", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_Q, App.KY_Q, pDatabase, "CTRL-Q", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_W, App.KY_W, pDatabase, "CTRL-W", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_E, App.KY_E, pDatabase, "CTRL-E", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_R, App.KY_R, pDatabase, "CTRL-R", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_T, App.KY_T, pDatabase, "CTRL-T", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_Y, App.KY_Y, pDatabase, "CTRL-Y", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_U, App.KY_U, pDatabase, "CTRL-U", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_I, App.KY_I, pDatabase, "CTRL-I", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_O, App.KY_O, pDatabase, "CTRL-O", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_P, App.KY_P, pDatabase, "CTRL-P", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_OPEN_BRACKET, App.KY_OPEN_BRACKET, pDatabase, "[", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CLOSE_BRACKET, App.KY_CLOSE_BRACKET, pDatabase, "]", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_BACKSLASH, App.KY_SEPARATOR, pDatabase, "\\", App.KY_CTRL)

	# Map third row
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CAPSLOCK, App.KY_CAPSLOCK, pDatabase, "CAPS", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_A, App.KY_A, pDatabase, "CTRL-A", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_S, App.KY_S, pDatabase, "CTRL-S", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_D, App.KY_D, pDatabase, "CTRL-D", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_F, App.KY_F, pDatabase, "CTRL-F", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_G, App.KY_G, pDatabase, "CTRL-G", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_H, App.KY_H, pDatabase, "CTRL-H", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_J, App.KY_J, pDatabase, "CTRL-J", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_K, App.KY_K, pDatabase, "CTRL-K", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_L, App.KY_L, pDatabase, "CTRL-L", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_SEMICOLON, App.KY_SEMICOLON, pDatabase, ";", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_QUOTE, App.KY_QUOTE, pDatabase, "'", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_RETURN, App.KY_RETURN, pDatabase, "ENTER", App.KY_CTRL)

	# Map fourth row
	App.g_kInputManager.RegisterUnicodeKey(App.WC_SHIFT, App.KY_SHIFT, pDatabase, "SHIFT", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_Z, App.KY_Z, pDatabase, "CTRL-Z", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_X, App.KY_X, pDatabase, "CTRL-X", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_C, App.KY_C, pDatabase, "CTRL-C", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_V, App.KY_V, pDatabase, "CTRL-V", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_B, App.KY_B, pDatabase, "CTRL-B", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_N, App.KY_N, pDatabase, "CTRL-N", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL_M, App.KY_M, pDatabase, "CTRL-M", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_COMMA, App.KY_COMMA, pDatabase, ",", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_PERIOD, App.KY_PERIOD, pDatabase, ".", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_SLASH, App.KY_SLASH, pDatabase, "/", App.KY_CTRL)

	# Map fifth row
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL, App.KY_CTRL, pDatabase, "CTRL", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT, App.KY_ALT, pDatabase, "ALT", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_SPACE, App.KY_SPACE, pDatabase, "SPACE", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALTGR, App.KY_ALTGR, pDatabase, "ALTGR", App.KY_CTRL)

	# Map middle column (Top, 1st, 2nd, 4th, 5th)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_PRINTSCREEN, App.KY_PRINTSCREEN, pDatabase, "PRINT SCRN", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_PAUSE, App.KY_PAUSE, pDatabase, "PAUSE", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_SCROLL, App.KY_SCROLL, pDatabase, "SCRL LOCK", App.KY_CTRL)

	App.g_kInputManager.RegisterUnicodeKey(App.WC_INSERT, App.KY_INSERT, pDatabase, "INS", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_HOME, App.KY_HOME, pDatabase, "HOME", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_PAGEUP, App.KY_PAGEUP, pDatabase, "PG UP", App.KY_CTRL)

	App.g_kInputManager.RegisterUnicodeKey(App.WC_DELETE, App.KY_DELETE, pDatabase, "DEL", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_END, App.KY_END, pDatabase, "END", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_PAGEDOWN, App.KY_PAGEDOWN, pDatabase, "PG DN", App.KY_CTRL)

	App.g_kInputManager.RegisterUnicodeKey(App.WC_UP, App.KY_UP, pDatabase, "UP", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_DOWN, App.KY_DOWN, pDatabase, "DOWN", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_LEFT, App.KY_LEFT, pDatabase, "LEFT", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_RIGHT, App.KY_RIGHT, pDatabase, "RIGHT", App.KY_CTRL)

	# Map Numkeys
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMLOCK, App.KY_NUMLOCK, pDatabase, "NUM LOCK", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_DIVIDE, App.KY_DIVIDE, pDatabase, "Num /", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_MULTIPLY, App.KY_MULTIPLY, pDatabase, "Num *", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_SUBTRACT, App.KY_SUBTRACT, pDatabase, "Num -", App.KY_CTRL)

	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD7, App.KY_NUMPAD7, pDatabase, "Num 7", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD8, App.KY_NUMPAD8, pDatabase, "Num 8", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD9, App.KY_NUMPAD9, pDatabase, "Num 9", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ADD, App.KY_ADD, pDatabase, "Num +", App.KY_CTRL)

	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD4, App.KY_NUMPAD4, pDatabase, "Num 4", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD5, App.KY_NUMPAD5, pDatabase, "Num 5", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD6, App.KY_NUMPAD6, pDatabase, "Num 6", App.KY_CTRL)

	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD1, App.KY_NUMPAD1, pDatabase, "Num 1", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD2, App.KY_NUMPAD2, pDatabase, "Num 2", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD3, App.KY_NUMPAD3, pDatabase, "Num 3", App.KY_CTRL)

	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD0, App.KY_NUMPAD0, pDatabase, "Num 0", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_DECIMAL, App.KY_DECIMAL, pDatabase, "Num .", App.KY_CTRL)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPADENTER, App.KY_NUMPADENTER, pDatabase, "Num Enter", App.KY_CTRL)


	### ALTGR STATE ###
	# Map top row (Esc, function keys, printscreen, scrolllock, pause)
	#App.g_kInputManager.RegisterUnicodeKey(App.WC_ESCAPE, App.KY_ESCAPE, pDatabase, "ESC", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_F1, App.KY_F1, pDatabase, "ALT-F1", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_F2, App.KY_F2, pDatabase, "ALT-F2", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_F3, App.KY_F3, pDatabase, "ALT-F3", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_F4, App.KY_F4, pDatabase, "ALT-F4", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_F5, App.KY_F5, pDatabase, "ALT-F5", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_F6, App.KY_F6, pDatabase, "ALT-F6", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_F7, App.KY_F7, pDatabase, "ALT-F7", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_F8, App.KY_F8, pDatabase, "ALT-F8", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_F9, App.KY_F9, pDatabase, "ALT-F9", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_F10, App.KY_F10, pDatabase, "ALT-F10", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_F11, App.KY_F11, pDatabase, "ALT-F11", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT_F12, App.KY_F12, pDatabase, "ALT-F12", App.KY_ALTGR)

	# Map the first row
	#App.g_kInputManager.RegisterUnicodeKey(App.WC_SPLIT_SEPARATOR, App.KY_BACKQUOTE, pDatabase, "Split Separator", App.KY_ALTGR)
	#App.g_kInputManager.RegisterUnicodeKey(App.WC_EURO_SIGN, App.KY_1, pDatabase, "Euro Sign", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_BACKSPACE, App.KY_BACKSPACE, pDatabase, "BACKSP", App.KY_ALTGR)

	# Map the second row
	App.g_kInputManager.RegisterUnicodeKey(App.WC_TAB, App.KY_TAB, pDatabase, "TAB", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_E_ACUTE, App.KY_E, pDatabase, "e ACUTE", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_U_ACUTE, App.KY_E, pDatabase, "u ACUTE", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_I_ACUTE, App.KY_E, pDatabase, "i ACUTE", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_O_ACUTE, App.KY_E, pDatabase, "o ACUTE", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_BACKSLASH, App.KY_SEPARATOR, pDatabase, "\\", App.KY_ALTGR)

	# Map third row
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CAPSLOCK, App.KY_CAPSLOCK, pDatabase, "CAPS", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_A_ACUTE, App.KY_A, pDatabase, "a ACUTE", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_RETURN, App.KY_RETURN, pDatabase, "ENTER", App.KY_ALTGR)

	# Map fourth row
	App.g_kInputManager.RegisterUnicodeKey(App.WC_SHIFT, App.KY_SHIFT, pDatabase, "SHIFT", App.KY_ALTGR)

	# Map fifth row
	App.g_kInputManager.RegisterUnicodeKey(App.WC_CTRL, App.KY_CTRL, pDatabase, "CTRL", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALT, App.KY_ALT, pDatabase, "ALT", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_SPACE, App.KY_SPACE, pDatabase, "SPACE", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ALTGR, App.KY_ALTGR, pDatabase, "ALTGR", App.KY_ALTGR)

	# Map middle column (Top, 1st, 2nd, 4th, 5th)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_PRINTSCREEN, App.KY_PRINTSCREEN, pDatabase, "PRINT SCRN", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_PAUSE, App.KY_PAUSE, pDatabase, "PAUSE", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_SCROLL, App.KY_SCROLL, pDatabase, "SCRL LOCK", App.KY_ALTGR)

	App.g_kInputManager.RegisterUnicodeKey(App.WC_INSERT, App.KY_INSERT, pDatabase, "INS", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_HOME, App.KY_HOME, pDatabase, "HOME", App.KY_ALTGR)

	App.g_kInputManager.RegisterUnicodeKey(App.WC_PAGEUP, App.KY_PAGEUP, pDatabase, "PG UP", App.KY_ALTGR)

	App.g_kInputManager.RegisterUnicodeKey(App.WC_DELETE, App.KY_DELETE, pDatabase, "DEL", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_END, App.KY_END, pDatabase, "END", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_PAGEDOWN, App.KY_PAGEDOWN, pDatabase, "PG DN", App.KY_ALTGR)

	App.g_kInputManager.RegisterUnicodeKey(App.WC_UP, App.KY_UP, pDatabase, "UP", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_DOWN, App.KY_DOWN, pDatabase, "DOWN", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_LEFT, App.KY_LEFT, pDatabase, "LEFT", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_RIGHT, App.KY_RIGHT, pDatabase, "RIGHT", App.KY_ALTGR)

	# Map Numkeys
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMLOCK, App.KY_NUMLOCK, pDatabase, "NUM LOCK", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_DIVIDE, App.KY_DIVIDE, pDatabase, "Num /", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_MULTIPLY, App.KY_MULTIPLY, pDatabase, "Num *", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_SUBTRACT, App.KY_SUBTRACT, pDatabase, "Num -", App.KY_ALTGR)

	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD7, App.KY_NUMPAD7, pDatabase, "Num 7", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD8, App.KY_NUMPAD8, pDatabase, "Num 8", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD9, App.KY_NUMPAD9, pDatabase, "Num 9", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_ADD, App.KY_ADD, pDatabase, "Num +", App.KY_ALTGR)

	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD4, App.KY_NUMPAD4, pDatabase, "Num 4", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD5, App.KY_NUMPAD5, pDatabase, "Num 5", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD6, App.KY_NUMPAD6, pDatabase, "Num 6", App.KY_ALTGR)

	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD1, App.KY_NUMPAD1, pDatabase, "Num 1", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD2, App.KY_NUMPAD2, pDatabase, "Num 2", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD3, App.KY_NUMPAD3, pDatabase, "Num 3", App.KY_ALTGR)

	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPAD0, App.KY_NUMPAD0, pDatabase, "Num 0", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_DECIMAL, App.KY_DECIMAL, pDatabase, "Num .", App.KY_ALTGR)
	App.g_kInputManager.RegisterUnicodeKey(App.WC_NUMPADENTER, App.KY_NUMPADENTER, pDatabase, "Num Enter", App.KY_ALTGR)

	### NON KEYBOARD ###
	# Mouse and keyboard stuff
	App.g_kInputManager.RegisterUnicodeKey(App.WC_SCROLL_WHEEL_UP, App.KY_SCROLL_WHEEL_UP, pDatabase, "SCRL WHL UP")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_SCROLL_WHEEL_DOWN, App.KY_SCROLL_WHEEL_DOWN, pDatabase, "SCRL WHL DN")

	App.g_kInputManager.RegisterUnicodeKey(App.WC_LBUTTON, App.KY_LBUTTON, pDatabase, "LButton")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_MBUTTON, App.KY_MBUTTON, pDatabase, "MButton")
	App.g_kInputManager.RegisterUnicodeKey(App.WC_RBUTTON, App.KY_RBUTTON, pDatabase, "RButton")

	if (pDatabase):
		App.g_kLocalizationManager.Unload(pDatabase)

