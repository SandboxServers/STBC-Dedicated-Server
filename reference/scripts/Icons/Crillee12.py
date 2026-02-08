import App

# Function to load Crillee12 font.
def LoadCrillee12(Crillee12 = None):
	
	if Crillee12 is None:
		# Create font group.
		Crillee12 = App.g_kFontManager.CreateFontGroup("Crillee", 12.0)
		# Add Crillee12 font group to FontManager
		App.g_kFontManager.AddFontGroup(Crillee12)

	# Load font texture
	pTextureHandle = Crillee12.LoadIconTexture('Data/Icons/Crillee12.tga')

	# Set spacing
	Crillee12.SetHorizontalSpacing(0.0)
	Crillee12.SetVerticalSpacing(4.0)
	Crillee12.SetSpaceWidth(8.0)
	Crillee12.SetTabWidth(32.0)

	# Special characters
	Crillee12.SetIconLocation(0,			pTextureHandle, 231, 150, 13, 20) # Box shape
	Crillee12.SetIconLocation(App.WC_CURSOR,pTextureHandle, 211, 150,  3, 25) # Cursor
	Crillee12.SetIconLocation(App.WC_TAB,	pTextureHandle, 215, 150,  1, 25) # Tab
	Crillee12.SetIconLocation(App.WC_SPACE,	pTextureHandle, 215, 150,  1, 25) # Space

	# Define icon locations
	Crillee12.SetIconLocation( 33, pTextureHandle,   0,   0,  6, 20) # !
	Crillee12.SetIconLocation( 34, pTextureHandle,   7,   0,  6, 10) # "
	Crillee12.SetIconLocation( 35, pTextureHandle,  14,   0, 15, 20) # #
	Crillee12.SetIconLocation( 36, pTextureHandle,  30,   0, 10, 22) # $
	Crillee12.SetIconLocation( 37, pTextureHandle,  41,   0, 16, 20) # %
	Crillee12.SetIconLocation( 38, pTextureHandle,  58,   0, 13, 20) # &
	Crillee12.SetIconLocation( 39, pTextureHandle,  72,   0,  3, 10) # '
	Crillee12.SetIconLocation( 40, pTextureHandle,  76,   0,  6, 22) # (
	Crillee12.SetIconLocation( 41, pTextureHandle,  83,   0,  6, 22) # )
	Crillee12.SetIconLocation( 42, pTextureHandle,  90,   0,  7, 13) # *
	Crillee12.SetIconLocation( 43, pTextureHandle,  98,   0, 11, 20) # +
	Crillee12.SetIconLocation( 44, pTextureHandle, 110,   0,  5, 23) # ,
	Crillee12.SetIconLocation( 45, pTextureHandle, 116,   0,  5, 16) # -
	Crillee12.SetIconLocation( 46, pTextureHandle, 122,   0,  4, 21) # .
	Crillee12.SetIconLocation( 47, pTextureHandle, 127,   0, 13, 21) # /
	Crillee12.SetIconLocation( 48, pTextureHandle, 141,   0, 12, 20) # 0
	Crillee12.SetIconLocation( 49, pTextureHandle, 154,   0,  6, 20) # 1
	Crillee12.SetIconLocation( 50, pTextureHandle, 161,   0, 12, 20) # 2
	Crillee12.SetIconLocation( 51, pTextureHandle, 174,   0, 12, 20) # 3
	Crillee12.SetIconLocation( 52, pTextureHandle, 187,   0, 12, 20) # 4
	Crillee12.SetIconLocation( 53, pTextureHandle, 200,   0, 12, 20) # 5
	Crillee12.SetIconLocation( 54, pTextureHandle, 213,   0, 11, 20) # 6
	Crillee12.SetIconLocation( 55, pTextureHandle, 225,   0, 11, 20) # 7
	Crillee12.SetIconLocation( 56, pTextureHandle, 237,   0, 12, 20) # 8
	Crillee12.SetIconLocation( 57, pTextureHandle,   0,  25, 11, 20) # 9
	Crillee12.SetIconLocation( 58, pTextureHandle,  12,  25,  4, 20) # :
	Crillee12.SetIconLocation( 59, pTextureHandle,  17,  25,  5, 22) # ;
	Crillee12.SetIconLocation( 60, pTextureHandle,  23,  25, 12, 19) # <
	Crillee12.SetIconLocation( 61, pTextureHandle,  36,  25, 11, 18) # =
	Crillee12.SetIconLocation( 62, pTextureHandle,  48,  25, 11, 20) # >
	Crillee12.SetIconLocation( 63, pTextureHandle,  60,  25,  9, 20) # ?
	Crillee12.SetIconLocation( 64, pTextureHandle,  70,  25, 16, 21) # @
	Crillee12.SetIconLocation( 65, pTextureHandle,  87,  25, 14, 20) # A
	Crillee12.SetIconLocation( 66, pTextureHandle, 102,  25, 14, 20) # B
	Crillee12.SetIconLocation( 67, pTextureHandle, 117,  25, 13, 20) # C
	Crillee12.SetIconLocation( 68, pTextureHandle, 131,  25, 15, 20) # D
	Crillee12.SetIconLocation( 69, pTextureHandle, 147,  25, 13, 20) # E
	Crillee12.SetIconLocation( 70, pTextureHandle, 161,  25, 13, 20) # F
	Crillee12.SetIconLocation( 71, pTextureHandle, 175,  25, 14, 20) # G
	Crillee12.SetIconLocation( 72, pTextureHandle, 190,  25, 16, 20) # H
	Crillee12.SetIconLocation( 73, pTextureHandle, 207,  25,  8, 20) # I
	Crillee12.SetIconLocation( 74, pTextureHandle, 216,  25, 12, 20) # J
	Crillee12.SetIconLocation( 75, pTextureHandle, 229,  25, 15, 20) # K
	Crillee12.SetIconLocation( 76, pTextureHandle, 245,  25, 11, 20) # L
	Crillee12.SetIconLocation( 77, pTextureHandle,   0,  50, 18, 20) # M
	Crillee12.SetIconLocation( 78, pTextureHandle,  19,  50, 15, 20) # N
	Crillee12.SetIconLocation( 79, pTextureHandle,  35,  50, 14, 20) # O
	Crillee12.SetIconLocation( 80, pTextureHandle,  50,  50, 15, 20) # P
	Crillee12.SetIconLocation( 81, pTextureHandle,  66,  50, 14, 22) # Q
	Crillee12.SetIconLocation( 82, pTextureHandle,  81,  50, 14, 20) # R
	Crillee12.SetIconLocation( 83, pTextureHandle,  96,  50, 13, 20) # S
	Crillee12.SetIconLocation( 84, pTextureHandle, 110,  50, 13, 20) # T
	Crillee12.SetIconLocation( 85, pTextureHandle, 124,  50, 14, 20) # U
	Crillee12.SetIconLocation( 86, pTextureHandle, 139,  50, 14, 20) # V
	Crillee12.SetIconLocation( 87, pTextureHandle, 154,  50, 20, 20) # W
	Crillee12.SetIconLocation( 88, pTextureHandle, 175,  50, 16, 20) # X
	Crillee12.SetIconLocation( 89, pTextureHandle, 192,  50, 12, 20) # Y
	Crillee12.SetIconLocation( 90, pTextureHandle, 205,  50, 15, 20) # Z
	Crillee12.SetIconLocation( 91, pTextureHandle, 221,  50,  8, 21) # [
	Crillee12.SetIconLocation( 92, pTextureHandle, 230,  50,  7, 19) # \
	Crillee12.SetIconLocation( 93, pTextureHandle, 238,  50,  8, 21) # ]
	Crillee12.SetIconLocation( 94, pTextureHandle,   0,  75, 11, 14) # ^
	Crillee12.SetIconLocation( 95, pTextureHandle,  12,  75, 11, 23) # _
	Crillee12.SetIconLocation( 96, pTextureHandle,  24,  75,  4,  9) # `
	Crillee12.SetIconLocation( 97, pTextureHandle,  29,  75, 13, 20) # a
	Crillee12.SetIconLocation( 98, pTextureHandle,  43,  75, 13, 20) # b
	Crillee12.SetIconLocation( 99, pTextureHandle,  57,  75, 12, 20) # c
	Crillee12.SetIconLocation(100, pTextureHandle,  70,  75, 14, 20) # d
	Crillee12.SetIconLocation(101, pTextureHandle,  85,  75, 12, 20) # e
	Crillee12.SetIconLocation(102, pTextureHandle,  98,  75, 11, 20) # f
	Crillee12.SetIconLocation(103, pTextureHandle, 110,  75, 14, 23) # g
	Crillee12.SetIconLocation(104, pTextureHandle, 125,  75, 13, 20) # h
	Crillee12.SetIconLocation(105, pTextureHandle, 139,  75,  7, 20) # i
	Crillee12.SetIconLocation(106, pTextureHandle, 147,  75, 11, 24) # j
	Crillee12.SetIconLocation(107, pTextureHandle, 159,  75, 13, 20) # k
	Crillee12.SetIconLocation(108, pTextureHandle, 173,  75,  7, 20) # l
	Crillee12.SetIconLocation(109, pTextureHandle, 181,  75, 19, 20) # m
	Crillee12.SetIconLocation(110, pTextureHandle, 201,  75, 12, 20) # n
	Crillee12.SetIconLocation(111, pTextureHandle, 214,  75, 12, 20) # o
	Crillee12.SetIconLocation(112, pTextureHandle, 227,  75, 14, 24) # p
	Crillee12.SetIconLocation(113, pTextureHandle, 242,  75, 13, 24) # q
	Crillee12.SetIconLocation(114, pTextureHandle,   0, 100, 11, 20) # r
	Crillee12.SetIconLocation(115, pTextureHandle,  12, 100, 12, 20) # s
	Crillee12.SetIconLocation(116, pTextureHandle,  25, 100,  9, 20) # t
	Crillee12.SetIconLocation(117, pTextureHandle,  35, 100, 12, 20) # u
	Crillee12.SetIconLocation(118, pTextureHandle,  48, 100, 11, 20) # v
	Crillee12.SetIconLocation(119, pTextureHandle,  60, 100, 17, 20) # w
	Crillee12.SetIconLocation(120, pTextureHandle,  78, 100, 13, 20) # x
	Crillee12.SetIconLocation(121, pTextureHandle,  92, 100, 13, 24) # y
	Crillee12.SetIconLocation(122, pTextureHandle, 106, 100, 12, 20) # z
	Crillee12.SetIconLocation(123, pTextureHandle, 119, 100,  9, 22) # {
	Crillee12.SetIconLocation(124, pTextureHandle, 129, 100,  4, 20) # |
	Crillee12.SetIconLocation(125, pTextureHandle, 134, 100,  9, 22) # }
	Crillee12.SetIconLocation(126, pTextureHandle, 144, 100, 12, 15) # ~

	Crillee12.SetIconLocation(132, pTextureHandle,   7,   0,  6, 25, App.TGIconGroup.ROTATE_180) # " (upsidedown ")
	Crillee12.SetIconLocation(161, pTextureHandle,   0,   0,  6, 25, App.TGIconGroup.ROTATE_180) # ¡ (upsidedown !)
	Crillee12.SetIconLocation(162, pTextureHandle,  30, 150, 12, 23) # ¢
	Crillee12.SetIconLocation(163, pTextureHandle,  43, 150, 13, 21) # £
	Crillee12.SetIconLocation(165, pTextureHandle,  57, 150, 12, 20) # ¥
	Crillee12.SetIconLocation(169, pTextureHandle, 231, 150, 20, 20) # ©
	Crillee12.SetIconLocation(180, pTextureHandle,  24,  75,  4,  9, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_HORIZONTAL) # ´
	Crillee12.SetIconLocation(191, pTextureHandle, 185, 150,  9, 20) # ¿
	Crillee12.SetIconLocation(192, pTextureHandle,  70, 150, 14, 20) # À
	Crillee12.SetIconLocation(193, pTextureHandle,   0, 175, 14, 20) # Á
	Crillee12.SetIconLocation(194, pTextureHandle,  15, 175, 14, 20) # Â
	Crillee12.SetIconLocation(195, pTextureHandle,  30, 175, 15, 20) # Ã
	Crillee12.SetIconLocation(196, pTextureHandle,  77, 125, 14, 20) # Ä
	Crillee12.SetIconLocation(197, pTextureHandle,  92, 125, 14, 20) # Å
	Crillee12.SetIconLocation(198, pTextureHandle, 143, 125, 23, 20) # Æ
	Crillee12.SetIconLocation(199, pTextureHandle, 157, 100, 13, 24) # Ç
	Crillee12.SetIconLocation(200, pTextureHandle,  46, 175, 13, 20) # È
	Crillee12.SetIconLocation(201, pTextureHandle, 107, 125, 13, 20) # É
	Crillee12.SetIconLocation(202, pTextureHandle,  60, 175, 13, 20) # Ê
	Crillee12.SetIconLocation(203, pTextureHandle,  74, 175, 13, 20) # Ë
	Crillee12.SetIconLocation(204, pTextureHandle,  86, 150,  9, 20) # Ì
	Crillee12.SetIconLocation(205, pTextureHandle,  96, 150,  9, 20) # Í
	Crillee12.SetIconLocation(206, pTextureHandle,  88, 175,  9, 20) # Î
	Crillee12.SetIconLocation(207, pTextureHandle,  98, 175, 10, 20) # Ï
	Crillee12.SetIconLocation(209, pTextureHandle, 168, 150, 16, 20) # Ñ
	Crillee12.SetIconLocation(210, pTextureHandle, 109, 175, 14, 20) # Ò
	Crillee12.SetIconLocation(211, pTextureHandle, 124, 175, 14, 20) # Ó
	Crillee12.SetIconLocation(212, pTextureHandle, 167, 125, 14, 20) # Ô
	Crillee12.SetIconLocation(213, pTextureHandle, 139, 175, 14, 20) # Õ
	Crillee12.SetIconLocation(214, pTextureHandle,   0, 150, 14, 20) # Ö
	Crillee12.SetIconLocation(216, pTextureHandle, 154, 175, 14, 20) # Ø
	Crillee12.SetIconLocation(217, pTextureHandle, 169, 175, 15, 20) # Ù
	Crillee12.SetIconLocation(218, pTextureHandle, 184, 175, 14, 20) # Ú
	Crillee12.SetIconLocation(219, pTextureHandle, 199, 175, 14, 20) # Û
	Crillee12.SetIconLocation(220, pTextureHandle,  15, 150, 14, 20) # Ü
	Crillee12.SetIconLocation(221, pTextureHandle, 214, 175, 12, 20) # Ý
 	Crillee12.SetIconLocation(223, pTextureHandle, 195, 150, 15, 24) # ß
	Crillee12.SetIconLocation(224, pTextureHandle, 225, 100, 13, 20) # à
	Crillee12.SetIconLocation(225, pTextureHandle, 106, 150, 13, 20) # á
	Crillee12.SetIconLocation(226, pTextureHandle, 197, 100, 13, 20) # â
	Crillee12.SetIconLocation(227, pTextureHandle, 226, 175, 13, 20) # ã
	Crillee12.SetIconLocation(228, pTextureHandle, 211, 100, 13, 20) # ä
	Crillee12.SetIconLocation(229, pTextureHandle, 239, 100, 13, 20) # å
	Crillee12.SetIconLocation(230, pTextureHandle, 121, 125, 21, 20) # æ
	Crillee12.SetIconLocation(231, pTextureHandle,   0, 125, 12, 23) # ç
	Crillee12.SetIconLocation(232, pTextureHandle,  39, 125, 12, 20) # è
	Crillee12.SetIconLocation(233, pTextureHandle, 184, 100, 12, 20) # é
	Crillee12.SetIconLocation(234, pTextureHandle,  13, 125, 12, 20) # ê
	Crillee12.SetIconLocation(235, pTextureHandle,  26, 125, 12, 20) # ë
	Crillee12.SetIconLocation(236, pTextureHandle,  70, 125,  6, 20) # ì
	Crillee12.SetIconLocation(237, pTextureHandle, 120, 150,  8, 20) # í
	Crillee12.SetIconLocation(238, pTextureHandle,  61, 125,  8, 20) # î
	Crillee12.SetIconLocation(239, pTextureHandle,  52, 125,  8, 20) # ï
	Crillee12.SetIconLocation(241, pTextureHandle, 155, 150, 12, 20) # ñ
	Crillee12.SetIconLocation(242, pTextureHandle, 195, 125, 12, 20) # ò
	Crillee12.SetIconLocation(243, pTextureHandle, 129, 150, 12, 20) # ó
	Crillee12.SetIconLocation(244, pTextureHandle, 240, 175, 12, 20) # ô
	Crillee12.SetIconLocation(245, pTextureHandle,   0, 200, 12, 20) # õ
	Crillee12.SetIconLocation(246, pTextureHandle, 182, 125, 12, 20) # ö
	Crillee12.SetIconLocation(248, pTextureHandle,  13, 200, 12, 20) # ø
	Crillee12.SetIconLocation(249, pTextureHandle, 221, 125, 12, 20) # ù
	Crillee12.SetIconLocation(250, pTextureHandle, 142, 150, 12, 20) # ú
	Crillee12.SetIconLocation(251, pTextureHandle, 208, 125, 12, 20) # û
	Crillee12.SetIconLocation(252, pTextureHandle, 171, 100, 12, 20) # ü
