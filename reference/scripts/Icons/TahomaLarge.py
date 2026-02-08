import App

# Function to load TahomaLarge font.
def LoadTahomaLarge(TahomaLarge = None):

	if TahomaLarge is None:
		# Create font group.
		TahomaLarge = App.g_kFontManager.CreateFontGroup("Tahoma", 14.0)
		# Add TahomaLarge font group to IconManager
		App.g_kFontManager.AddFontGroup(TahomaLarge)

	# Load font texture(s)
	pTextureHandle = TahomaLarge.LoadIconTexture('data/Icons/TahomaLarge0.tga')

	# Special characters
	TahomaLarge.SetIconLocation(0,				pTextureHandle, 162, 100, 13, 20) # Box shape
	TahomaLarge.SetIconLocation(App.WC_CURSOR,	pTextureHandle, 168, 152,  1, 19) # Cursor
	TahomaLarge.SetIconLocation(App.WC_TAB,		pTextureHandle, 172, 152,  1, 19) # Tab
	TahomaLarge.SetIconLocation(App.WC_SPACE,	pTextureHandle, 172, 152,  1, 19) # Space

	# Define icon locations
	TahomaLarge.SetIconLocation(  33, pTextureHandle,  164,  114,    4,   19 ) # '!'
	TahomaLarge.SetIconLocation(  34, pTextureHandle,   99,  152,    6,   19 ) # '"'
	TahomaLarge.SetIconLocation(  35, pTextureHandle,  183,  114,   12,   19 ) # '#'
	TahomaLarge.SetIconLocation(  36, pTextureHandle,  195,  114,    9,   19 ) # '$'
	TahomaLarge.SetIconLocation(  37, pTextureHandle,  204,  114,   16,   19 ) # '%'
	TahomaLarge.SetIconLocation(  38, pTextureHandle,  256,    0,    0,   19 ) # '&'
	TahomaLarge.SetIconLocation(  39, pTextureHandle,  253,  114,    3,   19 ) # '''
	TahomaLarge.SetIconLocation(  40, pTextureHandle,  241,  114,    6,   19 ) # '('
	TahomaLarge.SetIconLocation(  41, pTextureHandle,  247,  114,    6,   19 ) # ')'
	TahomaLarge.SetIconLocation(  42, pTextureHandle,  232,  114,    9,   19 ) # '*'
	TahomaLarge.SetIconLocation(  43, pTextureHandle,   27,  152,   12,   19 ) # '+'
	TahomaLarge.SetIconLocation(  44, pTextureHandle,   39,  152,    5,   19 ) # ','
	TahomaLarge.SetIconLocation(  45, pTextureHandle,    0,  152,    6,   19 ) # '-'
	TahomaLarge.SetIconLocation(  46, pTextureHandle,   56,  152,    5,   19 ) # '.'
	TahomaLarge.SetIconLocation(  47, pTextureHandle,   73,  152,    6,   19 ) # '/'
	TahomaLarge.SetIconLocation(  48, pTextureHandle,  150,  114,    9,   19 ) # '0'
	TahomaLarge.SetIconLocation(  49, pTextureHandle,   69,  114,    9,   19 ) # '1'
	TahomaLarge.SetIconLocation(  50, pTextureHandle,   78,  114,    9,   19 ) # '2'
	TahomaLarge.SetIconLocation(  51, pTextureHandle,   87,  114,    9,   19 ) # '3'
	TahomaLarge.SetIconLocation(  52, pTextureHandle,   96,  114,    9,   19 ) # '4'
	TahomaLarge.SetIconLocation(  53, pTextureHandle,  105,  114,    9,   19 ) # '5'
	TahomaLarge.SetIconLocation(  54, pTextureHandle,  114,  114,    9,   19 ) # '6'
	TahomaLarge.SetIconLocation(  55, pTextureHandle,  123,  114,    9,   19 ) # '7'
	TahomaLarge.SetIconLocation(  56, pTextureHandle,  132,  114,    9,   19 ) # '8'
	TahomaLarge.SetIconLocation(  57, pTextureHandle,  141,  114,    9,   19 ) # '9'
	TahomaLarge.SetIconLocation(  58, pTextureHandle,   93,  152,    6,   19 ) # ':'
	TahomaLarge.SetIconLocation(  59, pTextureHandle,   87,  152,    6,   19 ) # ';'
	TahomaLarge.SetIconLocation(  60, pTextureHandle,   44,  152,   12,   19 ) # '<'
	TahomaLarge.SetIconLocation(  61, pTextureHandle,   15,  152,   12,   19 ) # '='
	TahomaLarge.SetIconLocation(  62, pTextureHandle,   61,  152,   12,   19 ) # '>'
	TahomaLarge.SetIconLocation(  63, pTextureHandle,   79,  152,    8,   19 ) # '?'
	TahomaLarge.SetIconLocation(  64, pTextureHandle,  168,  114,   15,   19 ) # '@'
	TahomaLarge.SetIconLocation(  65, pTextureHandle,    0,    0,   11,   19 ) # 'A'
	TahomaLarge.SetIconLocation(  66, pTextureHandle,   11,    0,    9,   19 ) # 'B'
	TahomaLarge.SetIconLocation(  67, pTextureHandle,   20,    0,   10,   19 ) # 'C'
	TahomaLarge.SetIconLocation(  68, pTextureHandle,   30,    0,   11,   19 ) # 'D'
	TahomaLarge.SetIconLocation(  69, pTextureHandle,   41,    0,    9,   19 ) # 'E'
	TahomaLarge.SetIconLocation(  70, pTextureHandle,   50,    0,    8,   19 ) # 'F'
	TahomaLarge.SetIconLocation(  71, pTextureHandle,   58,    0,   11,   19 ) # 'G'
	TahomaLarge.SetIconLocation(  72, pTextureHandle,   69,    0,   11,   19 ) # 'H'
	TahomaLarge.SetIconLocation(  73, pTextureHandle,   80,    0,    6,   19 ) # 'I'
	TahomaLarge.SetIconLocation(  74, pTextureHandle,   86,    0,    7,   19 ) # 'J'
	TahomaLarge.SetIconLocation(  75, pTextureHandle,   93,    0,    9,   19 ) # 'K'
	TahomaLarge.SetIconLocation(  76, pTextureHandle,  102,    0,    8,   19 ) # 'L'
	TahomaLarge.SetIconLocation(  77, pTextureHandle,  110,    0,   12,   19 ) # 'M'
	TahomaLarge.SetIconLocation(  78, pTextureHandle,  122,    0,   11,   19 ) # 'N'
	TahomaLarge.SetIconLocation(  79, pTextureHandle,  133,    0,   12,   19 ) # 'O'
	TahomaLarge.SetIconLocation(  80, pTextureHandle,  145,    0,    9,   19 ) # 'P'
	TahomaLarge.SetIconLocation(  81, pTextureHandle,  154,    0,   12,   19 ) # 'Q'
	TahomaLarge.SetIconLocation(  82, pTextureHandle,  166,    0,   10,   19 ) # 'R'
	TahomaLarge.SetIconLocation(  83, pTextureHandle,  176,    0,    9,   19 ) # 'S'
	TahomaLarge.SetIconLocation(  84, pTextureHandle,  185,    0,   10,   19 ) # 'T'
	TahomaLarge.SetIconLocation(  85, pTextureHandle,  195,    0,   11,   19 ) # 'U'
	TahomaLarge.SetIconLocation(  86, pTextureHandle,  206,    0,   10,   19 ) # 'V'
	TahomaLarge.SetIconLocation(  87, pTextureHandle,  216,    0,   14,   19 ) # 'W'
	TahomaLarge.SetIconLocation(  88, pTextureHandle,  230,    0,    9,   19 ) # 'X'
	TahomaLarge.SetIconLocation(  89, pTextureHandle,  239,    0,   10,   19 ) # 'Y'
	TahomaLarge.SetIconLocation(  90, pTextureHandle,    0,   38,    9,   19 ) # 'Z'
	TahomaLarge.SetIconLocation(  91, pTextureHandle,  131,  152,    6,   19 ) # '['
	TahomaLarge.SetIconLocation(  92, pTextureHandle,  105,  152,    6,   19 ) # '\'
	TahomaLarge.SetIconLocation(  93, pTextureHandle,  117,  152,    6,   19 ) # ']'
	TahomaLarge.SetIconLocation(  94, pTextureHandle,  220,  114,   12,   19 ) # '^'
	TahomaLarge.SetIconLocation(  95, pTextureHandle,    6,  152,    9,   19 ) # '_'
	TahomaLarge.SetIconLocation(  96, pTextureHandle,  145,  152,    9,   19 ) # '`'
	TahomaLarge.SetIconLocation(  97, pTextureHandle,    9,   38,    8,   19 ) # 'a'
	TahomaLarge.SetIconLocation(  98, pTextureHandle,   17,   38,    9,   19 ) # 'b'
	TahomaLarge.SetIconLocation(  99, pTextureHandle,  249,    0,    7,   19 ) # 'c'
	TahomaLarge.SetIconLocation( 100, pTextureHandle,   26,   38,    9,   19 ) # 'd'
	TahomaLarge.SetIconLocation( 101, pTextureHandle,   35,   38,    8,   19 ) # 'e'
	TahomaLarge.SetIconLocation( 102, pTextureHandle,   43,   38,    5,   19 ) # 'f'
	TahomaLarge.SetIconLocation( 103, pTextureHandle,   48,   38,    9,   19 ) # 'g'
	TahomaLarge.SetIconLocation( 104, pTextureHandle,   57,   38,    9,   19 ) # 'h'
	TahomaLarge.SetIconLocation( 105, pTextureHandle,   66,   38,    4,   19 ) # 'i'
	TahomaLarge.SetIconLocation( 106, pTextureHandle,   70,   38,    5,   19 ) # 'j'
	TahomaLarge.SetIconLocation( 107, pTextureHandle,   75,   38,    8,   19 ) # 'k'
	TahomaLarge.SetIconLocation( 108, pTextureHandle,   83,   38,    4,   19 ) # 'l'
	TahomaLarge.SetIconLocation( 109, pTextureHandle,   87,   38,   14,   19 ) # 'm'
	TahomaLarge.SetIconLocation( 110, pTextureHandle,  101,   38,    9,   19 ) # 'n'
	TahomaLarge.SetIconLocation( 111, pTextureHandle,  110,   38,    9,   19 ) # 'o'
	TahomaLarge.SetIconLocation( 112, pTextureHandle,  119,   38,    9,   19 ) # 'p'
	TahomaLarge.SetIconLocation( 113, pTextureHandle,  128,   38,    9,   19 ) # 'q'
	TahomaLarge.SetIconLocation( 114, pTextureHandle,  137,   38,    6,   19 ) # 'r'
	TahomaLarge.SetIconLocation( 115, pTextureHandle,  143,   38,    7,   19 ) # 's'
	TahomaLarge.SetIconLocation( 116, pTextureHandle,  150,   38,    5,   19 ) # 't'
	TahomaLarge.SetIconLocation( 117, pTextureHandle,  155,   38,    9,   19 ) # 'u'
	TahomaLarge.SetIconLocation( 118, pTextureHandle,  164,   38,    8,   19 ) # 'v'
	TahomaLarge.SetIconLocation( 119, pTextureHandle,  172,   38,   12,   19 ) # 'w'
	TahomaLarge.SetIconLocation( 120, pTextureHandle,  184,   38,    8,   19 ) # 'x'
	TahomaLarge.SetIconLocation( 121, pTextureHandle,  192,   38,    8,   19 ) # 'y'
	TahomaLarge.SetIconLocation( 122, pTextureHandle,  200,   38,    7,   19 ) # 'z'
	TahomaLarge.SetIconLocation( 123, pTextureHandle,  137,  152,    8,   19 ) # '{'
	TahomaLarge.SetIconLocation( 124, pTextureHandle,  111,  152,    6,   19 ) # '|'
	TahomaLarge.SetIconLocation( 125, pTextureHandle,  123,  152,    8,   19 ) # '}'
	TahomaLarge.SetIconLocation( 126, pTextureHandle,  154,  152,   12,   19 ) # '~'

	TahomaLarge.SetIconLocation( 192, pTextureHandle,   20,   76,   11,   19 ) # 'À'
	TahomaLarge.SetIconLocation( 193, pTextureHandle,   31,   76,   11,   19 ) # 'Á'
	TahomaLarge.SetIconLocation( 194, pTextureHandle,   42,   76,   11,   19 ) # 'Â'

	TahomaLarge.SetIconLocation( 196, pTextureHandle,  207,   38,   11,   19 ) # 'Ä'

	TahomaLarge.SetIconLocation( 199, pTextureHandle,   77,   76,   10,   19 ) # 'Ç'

	TahomaLarge.SetIconLocation( 200, pTextureHandle,  103,   76,    9,   19 ) # 'È'
	TahomaLarge.SetIconLocation( 201, pTextureHandle,  112,   76,    9,   19 ) # 'É'
	TahomaLarge.SetIconLocation( 202, pTextureHandle,  121,   76,    9,   19 ) # 'Ê'
	TahomaLarge.SetIconLocation( 203, pTextureHandle,   94,   76,    9,   19 ) # 'Ë'
	TahomaLarge.SetIconLocation( 204, pTextureHandle,  168,   76,    6,   19 ) # 'Ì'
	TahomaLarge.SetIconLocation( 205, pTextureHandle,  174,   76,    6,   19 ) # 'Í'
	TahomaLarge.SetIconLocation( 206, pTextureHandle,  180,   76,    6,   19 ) # 'Î'
	TahomaLarge.SetIconLocation( 207, pTextureHandle,  162,   76,    6,   19 ) # 'Ï'

	TahomaLarge.SetIconLocation( 210, pTextureHandle,  202,   76,   12,   19 ) # 'Ò'
	TahomaLarge.SetIconLocation( 211, pTextureHandle,  214,   76,   12,   19 ) # 'Ó'
	TahomaLarge.SetIconLocation( 212, pTextureHandle,  226,   76,   12,   19 ) # 'Ô'

	TahomaLarge.SetIconLocation( 214, pTextureHandle,  226,   38,   12,   19 ) # 'Ö'

	TahomaLarge.SetIconLocation( 217, pTextureHandle,    9,  114,   11,   19 ) # 'Ù'
	TahomaLarge.SetIconLocation( 218, pTextureHandle,   20,  114,   11,   19 ) # 'Ú'
	TahomaLarge.SetIconLocation( 219, pTextureHandle,   31,  114,   11,   19 ) # 'Û'
	TahomaLarge.SetIconLocation( 220, pTextureHandle,    0,   76,   11,   19 ) # 'Ü'

	TahomaLarge.SetIconLocation( 223, pTextureHandle,   11,   76,    9,   19 ) # 'ß'
	TahomaLarge.SetIconLocation( 224, pTextureHandle,   53,   76,    8,   19 ) # 'à'
	TahomaLarge.SetIconLocation( 225, pTextureHandle,   61,   76,    8,   19 ) # 'á'
	TahomaLarge.SetIconLocation( 226, pTextureHandle,   69,   76,    8,   19 ) # 'â'

	TahomaLarge.SetIconLocation( 228, pTextureHandle,  218,   38,    8,   19 ) # 'ä'

	TahomaLarge.SetIconLocation( 231, pTextureHandle,   87,   76,    7,   19 ) # 'ç'
	TahomaLarge.SetIconLocation( 232, pTextureHandle,  138,   76,    8,   19 ) # 'è'
	TahomaLarge.SetIconLocation( 233, pTextureHandle,  146,   76,    8,   19 ) # 'é'
	TahomaLarge.SetIconLocation( 234, pTextureHandle,  154,   76,    8,   19 ) # 'ê'
	TahomaLarge.SetIconLocation( 235, pTextureHandle,  130,   76,    8,   19 ) # 'ë'
	TahomaLarge.SetIconLocation( 236, pTextureHandle,  190,   76,    4,   19 ) # 'ì'
	TahomaLarge.SetIconLocation( 237, pTextureHandle,  194,   76,    4,   19 ) # 'í'
	TahomaLarge.SetIconLocation( 238, pTextureHandle,  198,   76,    4,   19 ) # 'î'
	TahomaLarge.SetIconLocation( 239, pTextureHandle,  186,   76,    4,   19 ) # 'ï'

	TahomaLarge.SetIconLocation( 242, pTextureHandle,  238,   76,    9,   19 ) # 'ò'
	TahomaLarge.SetIconLocation( 243, pTextureHandle,  247,   76,    9,   19 ) # 'ó'
	TahomaLarge.SetIconLocation( 244, pTextureHandle,    0,  114,    9,   19 ) # 'ô'
	TahomaLarge.SetIconLocation( 246, pTextureHandle,  238,   38,    9,   19 ) # 'ö'

	TahomaLarge.SetIconLocation( 249, pTextureHandle,   42,  114,    9,   19 ) # 'ù'
	TahomaLarge.SetIconLocation( 250, pTextureHandle,   51,  114,    9,   19 ) # 'ú'
	TahomaLarge.SetIconLocation( 251, pTextureHandle,   60,  114,    9,   19 ) # 'û'
	TahomaLarge.SetIconLocation( 252, pTextureHandle,  247,   38,    9,   19 ) # 'ü'


	# Set spacing
	TahomaLarge.SetHorizontalSpacing(2.0)
	TahomaLarge.SetVerticalSpacing(2.0)
	TahomaLarge.SetSpaceWidth(6.0)
	TahomaLarge.SetTabWidth(24.0)
