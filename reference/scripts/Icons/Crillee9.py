import App

# Function to load Crillee9 font.
def LoadCrillee9(Crillee9 = None):
	
	if Crillee9 is None:
		# Create font group.
		Crillee9 = App.g_kFontManager.CreateFontGroup("Crillee", 9.0)
		# Add Crillee9 font group to FontManager
		App.g_kFontManager.AddFontGroup(Crillee9)

	# Load font texture
	pTextureHandle = Crillee9.LoadIconTexture('Data/Icons/Crillee9.tga')

	# Set spacing
	Crillee9.SetHorizontalSpacing(0.0)
	Crillee9.SetVerticalSpacing(2.0)
	Crillee9.SetSpaceWidth(8.0)
	Crillee9.SetTabWidth(32.0)

	# Special characters
	Crillee9.SetIconLocation(  0,			pTextureHandle,  85, 95, 10, 15) # Box shape
	Crillee9.SetIconLocation(App.WC_CURSOR,	pTextureHandle,  80, 95,  2, 19) # Cursor
	Crillee9.SetIconLocation(App.WC_TAB,	pTextureHandle,  83, 95,  1, 19) # Tab
	Crillee9.SetIconLocation(App.WC_SPACE,	pTextureHandle,  83, 95,  1, 19) # Space

	# Define icon locations
	Crillee9.SetIconLocation( 33, pTextureHandle,   0,   0,  4, 15) # !
	Crillee9.SetIconLocation( 34, pTextureHandle,   5,   0,  5,  8) # "
	Crillee9.SetIconLocation( 35, pTextureHandle,  11,   0, 11, 15) # #
	Crillee9.SetIconLocation( 36, pTextureHandle,  23,   0,  8, 17) # $
	Crillee9.SetIconLocation( 37, pTextureHandle,  32,   0, 13, 16) # %
	Crillee9.SetIconLocation( 38, pTextureHandle,  46,   0, 11, 16) # &
	Crillee9.SetIconLocation( 39, pTextureHandle,  58,   0,  2,  8) # '
	Crillee9.SetIconLocation( 40, pTextureHandle,  61,   0,  5, 17) # (
	Crillee9.SetIconLocation( 41, pTextureHandle,  67,   0,  5, 17) # )
	Crillee9.SetIconLocation( 42, pTextureHandle,  73,   0,  6, 10) # *
	Crillee9.SetIconLocation( 43, pTextureHandle,  80,   0,  9, 15) # +
	Crillee9.SetIconLocation( 44, pTextureHandle,  90,   0,  4, 17) # ,
	Crillee9.SetIconLocation( 45, pTextureHandle,  95,   0,  4, 12) # -
	Crillee9.SetIconLocation( 46, pTextureHandle, 100,   0,  3, 15) # .
	Crillee9.SetIconLocation( 47, pTextureHandle, 104,   0,  9, 15) # /
	Crillee9.SetIconLocation( 48, pTextureHandle, 114,   0,  9, 16) # 0
	Crillee9.SetIconLocation( 49, pTextureHandle, 124,   0,  5, 15) # 1
	Crillee9.SetIconLocation( 50, pTextureHandle, 130,   0, 10, 15) # 2
	Crillee9.SetIconLocation( 51, pTextureHandle, 141,   0,  9, 16) # 3
	Crillee9.SetIconLocation( 52, pTextureHandle, 151,   0,  8, 15) # 4
	Crillee9.SetIconLocation( 53, pTextureHandle, 160,   0,  9, 16) # 5
	Crillee9.SetIconLocation( 54, pTextureHandle, 170,   0,  9, 16) # 6
	Crillee9.SetIconLocation( 55, pTextureHandle, 180,   0,  9, 15) # 7
	Crillee9.SetIconLocation( 56, pTextureHandle, 190,   0,  9, 16) # 8
	Crillee9.SetIconLocation( 57, pTextureHandle, 200,   0,  8, 15) # 9
	Crillee9.SetIconLocation( 58, pTextureHandle, 209,   0,  3, 16) # :
	Crillee9.SetIconLocation( 59, pTextureHandle, 213,   0,  4, 17) # ;
	Crillee9.SetIconLocation( 60, pTextureHandle, 218,   0,  9, 15) # <
	Crillee9.SetIconLocation( 61, pTextureHandle, 228,   0,  9, 14) # =
	Crillee9.SetIconLocation( 62, pTextureHandle, 238,   0,  9, 15) # >
	Crillee9.SetIconLocation( 63, pTextureHandle, 248,   0,  7, 15) # ?
	Crillee9.SetIconLocation( 64, pTextureHandle,   0,  19, 12, 16) # @
	Crillee9.SetIconLocation( 65, pTextureHandle,  13,  19, 11, 15) # A
	Crillee9.SetIconLocation( 66, pTextureHandle,  25,  19, 11, 15) # B
	Crillee9.SetIconLocation( 67, pTextureHandle,  37,  19, 10, 15) # C
	Crillee9.SetIconLocation( 68, pTextureHandle,  48,  19, 11, 15) # D
	Crillee9.SetIconLocation( 69, pTextureHandle,  60,  19, 10, 15) # E
	Crillee9.SetIconLocation( 70, pTextureHandle,  71,  19, 10, 15) # F
	Crillee9.SetIconLocation( 71, pTextureHandle,  82,  19, 11, 15) # G
	Crillee9.SetIconLocation( 72, pTextureHandle,  94,  19, 12, 15) # H
	Crillee9.SetIconLocation( 73, pTextureHandle, 107,  19,  5, 15) # I
	Crillee9.SetIconLocation( 74, pTextureHandle, 113,  19,  9, 15) # J
	Crillee9.SetIconLocation( 75, pTextureHandle, 123,  19, 11, 15) # K
	Crillee9.SetIconLocation( 76, pTextureHandle, 135,  19,  8, 15) # L
	Crillee9.SetIconLocation( 77, pTextureHandle, 144,  19, 14, 15) # M
	Crillee9.SetIconLocation( 78, pTextureHandle, 159,  19, 11, 15) # N
	Crillee9.SetIconLocation( 79, pTextureHandle, 171,  19, 11, 15) # O
	Crillee9.SetIconLocation( 80, pTextureHandle, 183,  19, 11, 15) # P
	Crillee9.SetIconLocation( 81, pTextureHandle, 195,  19, 11, 17) # Q
	Crillee9.SetIconLocation( 82, pTextureHandle, 207,  19, 10, 15) # R
	Crillee9.SetIconLocation( 83, pTextureHandle, 218,  19, 10, 15) # S
	Crillee9.SetIconLocation( 84, pTextureHandle, 229,  19,  9, 15) # T
	Crillee9.SetIconLocation( 85, pTextureHandle, 239,  19, 11, 15) # U
	Crillee9.SetIconLocation( 86, pTextureHandle,   0,  38, 10, 15) # V
	Crillee9.SetIconLocation( 87, pTextureHandle,  11,  38, 15, 15) # W
	Crillee9.SetIconLocation( 88, pTextureHandle,  27,  38, 12, 15) # X
	Crillee9.SetIconLocation( 89, pTextureHandle,  40,  38, 10, 15) # Y
	Crillee9.SetIconLocation( 90, pTextureHandle,  51,  38, 11, 15) # Z
	Crillee9.SetIconLocation( 91, pTextureHandle,  63,  38,  7, 16) # [
	Crillee9.SetIconLocation( 92, pTextureHandle,  71,  38,  6, 15) # \
	Crillee9.SetIconLocation( 93, pTextureHandle,  78,  38,  7, 16) # ]
	Crillee9.SetIconLocation( 94, pTextureHandle,  86,  38,  9, 10) # ^
	Crillee9.SetIconLocation( 95, pTextureHandle,  96,  38,  8, 16) # _
	Crillee9.SetIconLocation( 96, pTextureHandle, 105,  38,  3,  6) # `
	Crillee9.SetIconLocation( 97, pTextureHandle, 109,  38, 10, 15) # a
	Crillee9.SetIconLocation( 98, pTextureHandle, 120,  38, 10, 15) # b
	Crillee9.SetIconLocation( 99, pTextureHandle, 131,  38,  8, 15) # c
	Crillee9.SetIconLocation(100, pTextureHandle, 140,  38, 10, 15) # d
	Crillee9.SetIconLocation(101, pTextureHandle, 151,  38,  9, 15) # e
	Crillee9.SetIconLocation(102, pTextureHandle, 161,  38,  8, 15) # f
	Crillee9.SetIconLocation(103, pTextureHandle, 170,  38, 10, 18) # g
	Crillee9.SetIconLocation(104, pTextureHandle, 181,  38, 10, 15) # h
	Crillee9.SetIconLocation(105, pTextureHandle, 192,  38,  4, 15) # i
	Crillee9.SetIconLocation(106, pTextureHandle, 197,  38,  9, 18) # j
	Crillee9.SetIconLocation(107, pTextureHandle, 207,  38,  9, 15) # k
	Crillee9.SetIconLocation(108, pTextureHandle, 217,  38,  6, 15) # l
	Crillee9.SetIconLocation(109, pTextureHandle, 224,  38, 15, 15) # m
	Crillee9.SetIconLocation(110, pTextureHandle, 240,  38,  9, 15) # n
	Crillee9.SetIconLocation(111, pTextureHandle,   0,  57,  9, 15) # o
	Crillee9.SetIconLocation(112, pTextureHandle,  10,  57, 10, 18) # p
	Crillee9.SetIconLocation(113, pTextureHandle,  21,  57, 10, 18) # q
	Crillee9.SetIconLocation(114, pTextureHandle,  32,  57,  8, 15) # r
	Crillee9.SetIconLocation(115, pTextureHandle,  41,  57,  9, 15) # s
	Crillee9.SetIconLocation(116, pTextureHandle,  51,  57,  8, 15) # t
	Crillee9.SetIconLocation(117, pTextureHandle,  60,  57, 10, 15) # u
	Crillee9.SetIconLocation(118, pTextureHandle,  71,  57,  9, 15) # v
	Crillee9.SetIconLocation(119, pTextureHandle,  81,  57, 13, 15) # w
	Crillee9.SetIconLocation(120, pTextureHandle,  95,  57,  9, 15) # x
	Crillee9.SetIconLocation(121, pTextureHandle, 105,  57,  9, 18) # y
	Crillee9.SetIconLocation(122, pTextureHandle, 115,  57,  9, 15) # z
	Crillee9.SetIconLocation(123, pTextureHandle, 125,  57,  6, 16) # {
	Crillee9.SetIconLocation(124, pTextureHandle, 132,  57,  3, 15) # |
	Crillee9.SetIconLocation(125, pTextureHandle, 136,  57,  6, 16) # }
	Crillee9.SetIconLocation(126, pTextureHandle, 143,  57,  9, 12) # ~

	Crillee9.SetIconLocation(132, pTextureHandle,   5,   0,  5, 19, App.TGIconGroup.ROTATE_180) # " (upsidedown ")
	Crillee9.SetIconLocation(161, pTextureHandle,   0,   0,  4, 19, App.TGIconGroup.ROTATE_180) # ¡ (upsidedown !)
	Crillee9.SetIconLocation(162, pTextureHandle, 200,  76,  8, 18) # ¢
	Crillee9.SetIconLocation(163, pTextureHandle, 209,  76, 10, 16) # £
	Crillee9.SetIconLocation(165, pTextureHandle, 220,  76, 10, 15) # ¥
	Crillee9.SetIconLocation(169, pTextureHandle,  96,  95, 15, 15) # ©
	Crillee9.SetIconLocation(180, pTextureHandle, 105,  38,  3,  6, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_HORIZONTAL) # ´
	Crillee9.SetIconLocation(191, pTextureHandle,  60,  95,  7, 15) # ¿
	Crillee9.SetIconLocation(192, pTextureHandle, 231,  76, 11, 15) # À
	Crillee9.SetIconLocation(193, pTextureHandle, 243,  76, 11, 15) # Á
	Crillee9.SetIconLocation(194, pTextureHandle, 112,  95, 11, 15) # Â
	Crillee9.SetIconLocation(195, pTextureHandle, 124,  95, 11, 15) # Ã
	Crillee9.SetIconLocation(196, pTextureHandle,  39,  76, 11, 15) # Ä
	Crillee9.SetIconLocation(197, pTextureHandle,  51,  76, 11, 15) # Å
	Crillee9.SetIconLocation(198, pTextureHandle,  92,  76, 19, 15) # Æ
	Crillee9.SetIconLocation(199, pTextureHandle, 153,  57, 10, 18) # Ç
	Crillee9.SetIconLocation(200, pTextureHandle, 136,  95, 10, 15) # È
	Crillee9.SetIconLocation(201, pTextureHandle,  63,  76, 10, 15) # É
	Crillee9.SetIconLocation(202, pTextureHandle, 147,  95, 10, 15) # Ê
	Crillee9.SetIconLocation(203, pTextureHandle, 158,  95, 10, 15) # Ë
	Crillee9.SetIconLocation(204, pTextureHandle, 169,  95,  5, 15) # Ì
	Crillee9.SetIconLocation(205, pTextureHandle, 175,  95,  6, 15) # Í
	Crillee9.SetIconLocation(206, pTextureHandle, 182,  95,  6, 15) # Î
	Crillee9.SetIconLocation(207, pTextureHandle, 189,  95,  6, 15) # Ï
	Crillee9.SetIconLocation(209, pTextureHandle,  48,  95, 11, 15) # Ñ
	Crillee9.SetIconLocation(210, pTextureHandle, 196,  95, 11, 15) # Ò
	Crillee9.SetIconLocation(211, pTextureHandle, 208,  95, 11, 15) # Ó
	Crillee9.SetIconLocation(212, pTextureHandle, 112,  76, 11, 15) # Ô
	Crillee9.SetIconLocation(213, pTextureHandle, 220,  95, 11, 15) # Õ
	Crillee9.SetIconLocation(214, pTextureHandle, 176,  76, 11, 15) # Ö
	Crillee9.SetIconLocation(216, pTextureHandle, 232,  95, 11, 15) # Ø
	Crillee9.SetIconLocation(217, pTextureHandle, 244,  95, 11, 15) # Ù
	Crillee9.SetIconLocation(218, pTextureHandle,   0, 113, 11, 15) # Ú
	Crillee9.SetIconLocation(219, pTextureHandle,  12, 113, 11, 15) # Û
	Crillee9.SetIconLocation(220, pTextureHandle, 188,  76, 11, 15) # Ü
	Crillee9.SetIconLocation(221, pTextureHandle,  24, 113, 10, 15) # Ý
 	Crillee9.SetIconLocation(223, pTextureHandle,  68,  95, 11, 15) # ß
	Crillee9.SetIconLocation(224, pTextureHandle, 207,  57, 10, 15) # à
	Crillee9.SetIconLocation(225, pTextureHandle,   0,  95, 10, 15) # á
	Crillee9.SetIconLocation(226, pTextureHandle, 185,  57, 10, 15) # â
	Crillee9.SetIconLocation(227, pTextureHandle,  35, 113, 10, 15) # ã
	Crillee9.SetIconLocation(228, pTextureHandle, 196,  57, 10, 15) # ä
	Crillee9.SetIconLocation(229, pTextureHandle, 218,  57, 10, 15) # å
	Crillee9.SetIconLocation(230, pTextureHandle,  74,  76, 17, 15) # æ
	Crillee9.SetIconLocation(231, pTextureHandle, 229,  57,  8, 18) # ç
	Crillee9.SetIconLocation(232, pTextureHandle,  10,  76,  9, 15) # è
	Crillee9.SetIconLocation(233, pTextureHandle, 175,  57,  9, 15) # é
	Crillee9.SetIconLocation(234, pTextureHandle, 238,  57,  9, 15) # ê
	Crillee9.SetIconLocation(235, pTextureHandle,   0,  76,  9, 15) # ë
	Crillee9.SetIconLocation(236, pTextureHandle,  34,  76,  4, 15) # ì
	Crillee9.SetIconLocation(237, pTextureHandle,  11,  95,  5, 15) # í
	Crillee9.SetIconLocation(238, pTextureHandle,  27,  76,  6, 15) # î
	Crillee9.SetIconLocation(239, pTextureHandle,  20,  76,  6, 15) # ï
	Crillee9.SetIconLocation(241, pTextureHandle,  38,  95,  9, 15) # ñ
	Crillee9.SetIconLocation(242, pTextureHandle, 134,  76,  9, 15) # ò
	Crillee9.SetIconLocation(243, pTextureHandle,  17,  95,  9, 15) # ó
	Crillee9.SetIconLocation(244, pTextureHandle,  46, 113,  9, 15) # ô
	Crillee9.SetIconLocation(245, pTextureHandle,  56, 113,  9, 15) # õ
	Crillee9.SetIconLocation(246, pTextureHandle, 124,  76,  9, 15) # ö
	Crillee9.SetIconLocation(248, pTextureHandle,  66, 113,  9, 15) # ø
	Crillee9.SetIconLocation(249, pTextureHandle, 155,  76, 10, 15) # ù
	Crillee9.SetIconLocation(250, pTextureHandle,  27,  95, 10, 15) # ú
	Crillee9.SetIconLocation(251, pTextureHandle, 144,  76, 10, 15) # û
	Crillee9.SetIconLocation(252, pTextureHandle, 164,  57, 10, 15) # ü
