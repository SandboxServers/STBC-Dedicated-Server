import App

# Function to load Crillee15 font.
def LoadCrillee15(Crillee15 = None):
	
	if Crillee15 is None:
		# Create font group.
		Crillee15 = App.g_kFontManager.CreateFontGroup("Crillee", 15.0)
		# Add Crillee15 font group to FontManager
		App.g_kFontManager.AddFontGroup(Crillee15)

	# Load font texture
	pMainTexHandle = Crillee15.LoadIconTexture('Data/Icons/Crillee15.tga')
	pIntlTexHandle = Crillee15.LoadIconTexture('Data/Icons/Crillee15Intl.tga')

	# Set spacing
	Crillee15.SetHorizontalSpacing(2.0)
	Crillee15.SetVerticalSpacing(5.0)
	Crillee15.SetSpaceWidth(10.0)
	Crillee15.SetTabWidth(40.0)

	# Special characters
	Crillee15.SetIconLocation(0,			pMainTexHandle, 240, 217, 15, 25) # Box shape
	Crillee15.SetIconLocation(App.WC_CURSOR,pMainTexHandle,   0, 248, 31,  3, App.TGIconGroup.ROTATE_90) # Cursor
	Crillee15.SetIconLocation(App.WC_TAB,	pMainTexHandle,   0, 252, 31,  1, App.TGIconGroup.ROTATE_90) # Tab
	Crillee15.SetIconLocation(App.WC_SPACE,	pMainTexHandle,   0, 252, 31,  1, App.TGIconGroup.ROTATE_90) # Space

	# Define icon locations
	Crillee15.SetIconLocation( 33, pMainTexHandle,   0,   0,  8, 25) # !
	Crillee15.SetIconLocation( 34, pMainTexHandle,   9,   0,  8, 13) # "
	Crillee15.SetIconLocation( 35, pMainTexHandle,  18,   0, 19, 25) # #
	Crillee15.SetIconLocation( 36, pMainTexHandle,  38,   0, 14, 28) # $
	Crillee15.SetIconLocation( 37, pMainTexHandle,  53,   0, 20, 25) # %
	Crillee15.SetIconLocation( 38, pMainTexHandle,  74,   0, 17, 25) # &
	Crillee15.SetIconLocation( 39, pMainTexHandle,  92,   0,  5, 25) # '
	Crillee15.SetIconLocation( 40, pMainTexHandle,  97,   0,  8, 26) # (
	Crillee15.SetIconLocation( 41, pMainTexHandle,  97,   0,  8, 31, App.TGIconGroup.ROTATE_180) # )
	Crillee15.SetIconLocation( 42, pMainTexHandle, 106,   0,  9, 15) # *
	Crillee15.SetIconLocation( 43, pMainTexHandle, 116,   0, 14, 24) # +
	Crillee15.SetIconLocation( 44, pMainTexHandle, 131,   0,  7, 28) # ,
	Crillee15.SetIconLocation( 45, pMainTexHandle, 139,   0,  7, 19) # -
	Crillee15.SetIconLocation( 46, pMainTexHandle, 147,   0,  5, 25) # .
	Crillee15.SetIconLocation( 47, pMainTexHandle, 153,   0, 16, 25) # /
	Crillee15.SetIconLocation( 48, pMainTexHandle, 170,   0, 15, 25) # 0
	Crillee15.SetIconLocation( 49, pMainTexHandle, 186,   0,  8, 25) # 1
	Crillee15.SetIconLocation( 50, pMainTexHandle, 195,   0, 16, 25) # 2
	Crillee15.SetIconLocation( 51, pMainTexHandle, 212,   0, 15, 25) # 3
	Crillee15.SetIconLocation( 52, pMainTexHandle, 229,   0, 14, 25) # 4
	Crillee15.SetIconLocation( 53, pMainTexHandle,   0,  31, 15, 25) # 5
	Crillee15.SetIconLocation( 54, pMainTexHandle,  16,  31, 14, 26) # 6
	Crillee15.SetIconLocation( 55, pMainTexHandle,  31,  31, 15, 25) # 7
	Crillee15.SetIconLocation( 56, pMainTexHandle,  47,  31, 15, 26) # 8
	Crillee15.SetIconLocation( 57, pMainTexHandle,  63,  31, 14, 25) # 9
	Crillee15.SetIconLocation( 58, pMainTexHandle, 244,   0,  5, 25) # :
	Crillee15.SetIconLocation( 59, pMainTexHandle,  78,  31,  6, 28) # ;
	Crillee15.SetIconLocation( 60, pMainTexHandle,  85,  31, 14, 25) # <
	Crillee15.SetIconLocation( 61, pMainTexHandle, 100,  31, 14, 25) # =
	Crillee15.SetIconLocation( 62, pMainTexHandle,  85,  31, 14, 25, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_HORIZONTAL) # >
	Crillee15.SetIconLocation( 63, pMainTexHandle, 115,  31, 12, 25) # ?
	Crillee15.SetIconLocation( 64, pMainTexHandle, 128,  31, 20, 26) # @
	Crillee15.SetIconLocation( 65, pMainTexHandle, 149,  31, 18, 25) # A
	Crillee15.SetIconLocation( 66, pMainTexHandle, 168,  31, 19, 25) # B
	Crillee15.SetIconLocation( 67, pMainTexHandle, 188,  31, 16, 25) # C
	Crillee15.SetIconLocation( 68, pMainTexHandle, 205,  31, 20, 25) # D
	Crillee15.SetIconLocation( 69, pMainTexHandle,   0,  62, 17, 25) # E
	Crillee15.SetIconLocation( 70, pMainTexHandle,  18,  62, 17, 25) # F
	Crillee15.SetIconLocation( 71, pMainTexHandle,  36,  62, 18, 25) # G
	Crillee15.SetIconLocation( 72, pMainTexHandle,  55,  62, 20, 25) # H
	Crillee15.SetIconLocation( 73, pMainTexHandle,  76,  62,  9, 25) # I
	Crillee15.SetIconLocation( 74, pMainTexHandle,  86,  62, 15, 25) # J
	Crillee15.SetIconLocation( 75, pMainTexHandle, 102,  62, 19, 25) # K
	Crillee15.SetIconLocation( 76, pMainTexHandle, 122,  62, 13, 25) # L
	Crillee15.SetIconLocation( 77, pMainTexHandle, 136,  62, 23, 25) # M
	Crillee15.SetIconLocation( 78, pMainTexHandle, 160,  62, 19, 25) # N
	Crillee15.SetIconLocation( 79, pMainTexHandle, 180,  62, 18, 25) # O
	Crillee15.SetIconLocation( 80, pMainTexHandle, 199,  62, 18, 25) # P
	Crillee15.SetIconLocation( 81, pMainTexHandle, 218,  62, 18, 28) # Q
	Crillee15.SetIconLocation( 82, pMainTexHandle, 237,  62, 19, 25) # R
	Crillee15.SetIconLocation( 83, pMainTexHandle,   0,  93, 17, 25) # S
	Crillee15.SetIconLocation( 84, pMainTexHandle,  18,  93, 15, 25) # T
	Crillee15.SetIconLocation( 85, pMainTexHandle,  34,  93, 18, 25) # U
	Crillee15.SetIconLocation( 86, pMainTexHandle,  53,  93, 18, 25) # V
	Crillee15.SetIconLocation( 87, pMainTexHandle,  72,  93, 25, 25) # W
	Crillee15.SetIconLocation( 88, pMainTexHandle,  98,  93, 20, 25) # X
	Crillee15.SetIconLocation( 89, pMainTexHandle, 119,  93, 16, 25) # Y
	Crillee15.SetIconLocation( 90, pMainTexHandle, 136,  93, 18, 25) # Z
	Crillee15.SetIconLocation( 91, pMainTexHandle, 155,  93, 10, 26) # [
	Crillee15.SetIconLocation( 92, pMainTexHandle, 166,  93,  9, 25) # \
	Crillee15.SetIconLocation( 93, pMainTexHandle, 155,  93, 10, 30, App.TGIconGroup.ROTATE_180) # ]
	Crillee15.SetIconLocation( 94, pMainTexHandle, 176,  93, 14, 18) # ^
	Crillee15.SetIconLocation( 95, pMainTexHandle, 191,  93, 13, 29) # _
	Crillee15.SetIconLocation( 96, pMainTexHandle, 205,  93,  5, 11) # `
	Crillee15.SetIconLocation( 97, pMainTexHandle, 211,  93, 15, 25) # a
	Crillee15.SetIconLocation( 98, pMainTexHandle, 227,  93, 16, 25) # b
	Crillee15.SetIconLocation( 99, pMainTexHandle,   0, 124, 15, 25) # c
	Crillee15.SetIconLocation(100, pMainTexHandle,  16, 124, 18, 25) # d
	Crillee15.SetIconLocation(101, pMainTexHandle,  35, 124, 15, 25) # e
	Crillee15.SetIconLocation(102, pMainTexHandle,  51, 124, 13, 25) # f
	Crillee15.SetIconLocation(103, pMainTexHandle,  65, 124, 17, 29) # g
	Crillee15.SetIconLocation(104, pMainTexHandle,  83, 124, 16, 25) # h
	Crillee15.SetIconLocation(105, pMainTexHandle, 100, 124,  8, 25) # i
	Crillee15.SetIconLocation(106, pMainTexHandle, 109, 124, 14, 30) # j
	Crillee15.SetIconLocation(107, pMainTexHandle, 124, 124, 15, 25) # k
	Crillee15.SetIconLocation(108, pMainTexHandle,  96, 247, 25,  8, App.TGIconGroup.ROTATE_90) # l
	Crillee15.SetIconLocation(109, pMainTexHandle, 140, 124, 24, 25) # m
	Crillee15.SetIconLocation(110, pMainTexHandle, 165, 124, 16, 25) # n
	Crillee15.SetIconLocation(111, pMainTexHandle, 182, 124, 16, 25) # o
	Crillee15.SetIconLocation(112, pMainTexHandle, 199, 124, 17, 29) # p
	Crillee15.SetIconLocation(113, pMainTexHandle, 217, 124, 17, 29) # q
	Crillee15.SetIconLocation(114, pMainTexHandle,   0, 155, 13, 25) # r
	Crillee15.SetIconLocation(115, pMainTexHandle,  14, 155, 15, 25) # s
	Crillee15.SetIconLocation(116, pMainTexHandle,  30, 155, 12, 25) # t
	Crillee15.SetIconLocation(117, pMainTexHandle,  43, 155, 16, 25) # u
	Crillee15.SetIconLocation(118, pMainTexHandle,  60, 155, 15, 25) # v
	Crillee15.SetIconLocation(119, pMainTexHandle,  76, 155, 21, 25) # w
	Crillee15.SetIconLocation(120, pMainTexHandle,  98, 155, 16, 25) # x
	Crillee15.SetIconLocation(121, pMainTexHandle, 115, 155, 16, 29) # y
	Crillee15.SetIconLocation(122, pMainTexHandle, 132, 155, 14, 25) # z
	Crillee15.SetIconLocation(123, pMainTexHandle, 244,  93, 10, 26) # {
	Crillee15.SetIconLocation(124, pMainTexHandle, 250,   0,  5, 25) # |
	Crillee15.SetIconLocation(125, pMainTexHandle, 244,  93, 10, 30, App.TGIconGroup.ROTATE_180) # }
	Crillee15.SetIconLocation(126, pMainTexHandle, 147, 155, 15, 21) # ~

	Crillee15.SetIconLocation(132, pMainTexHandle,   9,   0,  8, 31, App.TGIconGroup.ROTATE_180) # " (upsidedown ")
	Crillee15.SetIconLocation(161, pMainTexHandle,   0,   0,  8, 31, App.TGIconGroup.ROTATE_180) # ¡ (upsidedown !)
	Crillee15.SetIconLocation(162, pIntlTexHandle, 110,  31, 15, 29) # ¢
	Crillee15.SetIconLocation(163, pIntlTexHandle,  74,  62, 19, 27) # £
	Crillee15.SetIconLocation(165, pIntlTexHandle,  94,  62, 16, 25) # ¥
	Crillee15.SetIconLocation(169, pMainTexHandle, 226,  31, 25, 25) # ©
	Crillee15.SetIconLocation(180, pMainTexHandle, 205,  93,  5, 11, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_HORIZONTAL) # ´
	Crillee15.SetIconLocation(191, pMainTexHandle, 115,  31, 12, 31, App.TGIconGroup.ROTATE_180) # ¿
	Crillee15.SetIconLocation(192, pMainTexHandle,  96, 186, 18, 25) # À
	Crillee15.SetIconLocation(193, pMainTexHandle, 115, 186, 18, 25) # Á
	Crillee15.SetIconLocation(194, pMainTexHandle, 134, 186, 18, 25) # Â
	Crillee15.SetIconLocation(195, pIntlTexHandle,  57,   0, 19, 25) # Ã
	Crillee15.SetIconLocation(196, pMainTexHandle, 235, 124, 18, 25) # Ä
	Crillee15.SetIconLocation(197, pIntlTexHandle,  77,   0, 18, 25) # Å
	Crillee15.SetIconLocation(198, pIntlTexHandle,  26,   0, 30, 25) # Æ
	Crillee15.SetIconLocation(199, pMainTexHandle, 163, 155, 16, 29) # Ç
	Crillee15.SetIconLocation(200, pMainTexHandle, 153, 186, 17, 25) # È
	Crillee15.SetIconLocation(201, pMainTexHandle, 171, 186, 17, 25) # É
	Crillee15.SetIconLocation(202, pMainTexHandle, 189, 186, 17, 25) # Ê
	Crillee15.SetIconLocation(203, pMainTexHandle, 207, 186, 17, 25) # Ë
	Crillee15.SetIconLocation(204, pMainTexHandle, 246, 155, 10, 25) # Ì
	Crillee15.SetIconLocation(205, pMainTexHandle, 192, 245, 25, 10, App.TGIconGroup.ROTATE_90) # Í
	Crillee15.SetIconLocation(206, pMainTexHandle, 160, 244, 25, 11, App.TGIconGroup.ROTATE_90) # Î
	Crillee15.SetIconLocation(207, pMainTexHandle, 225, 186, 11, 25) # Ï
	Crillee15.SetIconLocation(209, pMainTexHandle, 209, 217, 19, 25) # Ñ
	Crillee15.SetIconLocation(210, pIntlTexHandle,  72,  31, 18, 25) # Ò
	Crillee15.SetIconLocation(211, pIntlTexHandle,  91,  31, 18, 25) # Ó
	Crillee15.SetIconLocation(212, pMainTexHandle,   0, 217, 18, 25) # Ô
	Crillee15.SetIconLocation(213, pIntlTexHandle,  34,  31, 18, 25) # Õ
	Crillee15.SetIconLocation(214, pMainTexHandle, 104, 217, 18, 25) # Ö
	Crillee15.SetIconLocation(216, pIntlTexHandle,  53,  31, 18, 25) # Ø
	Crillee15.SetIconLocation(217, pIntlTexHandle,  55,  62, 18, 25) # Ù
	Crillee15.SetIconLocation(218, pIntlTexHandle,   0,  62, 18, 25) # Ú
	Crillee15.SetIconLocation(219, pIntlTexHandle,  19,  62, 18, 25) # Û
	Crillee15.SetIconLocation(220, pMainTexHandle, 123, 217, 18, 25) # Ü
	Crillee15.SetIconLocation(221, pIntlTexHandle,  38,  62, 16, 25) # Ý
 	Crillee15.SetIconLocation(223, pMainTexHandle, 236, 186, 19, 30) # ß
	Crillee15.SetIconLocation(224, pMainTexHandle,  16, 186, 15, 25) # à
	Crillee15.SetIconLocation(225, pMainTexHandle, 142, 217, 15, 25) # á
	Crillee15.SetIconLocation(226, pMainTexHandle, 213, 155, 15, 25) # â
	Crillee15.SetIconLocation(227, pIntlTexHandle, 112,   0, 15, 25) # ã
	Crillee15.SetIconLocation(228, pMainTexHandle,   0, 186, 15, 25) # ä
	Crillee15.SetIconLocation(229, pIntlTexHandle,  96,   0, 15, 25) # å
	Crillee15.SetIconLocation(230, pIntlTexHandle,   0,   0, 25, 25) # æ
	Crillee15.SetIconLocation(231, pMainTexHandle,  32, 186, 15, 29) # ç
	Crillee15.SetIconLocation(232, pMainTexHandle,  80, 186, 15, 25) # è
	Crillee15.SetIconLocation(233, pMainTexHandle, 197, 155, 15, 25) # é
	Crillee15.SetIconLocation(234, pMainTexHandle,  48, 186, 15, 25) # ê
	Crillee15.SetIconLocation(235, pMainTexHandle,  64, 186, 15, 25) # ë
	Crillee15.SetIconLocation(236, pMainTexHandle,  64, 247, 25,  8, App.TGIconGroup.ROTATE_90) # ì
	Crillee15.SetIconLocation(237, pMainTexHandle,  32, 246, 25,  8, App.TGIconGroup.ROTATE_90) # í
	Crillee15.SetIconLocation(238, pMainTexHandle, 128, 245, 25, 10, App.TGIconGroup.ROTATE_90) # î
	Crillee15.SetIconLocation(239, pMainTexHandle, 224, 245, 25, 10, App.TGIconGroup.ROTATE_90) # ï
	Crillee15.SetIconLocation(241, pMainTexHandle, 192, 217, 16, 25) # ñ
	Crillee15.SetIconLocation(242, pMainTexHandle,  36, 217, 15, 25) # ò
	Crillee15.SetIconLocation(243, pMainTexHandle, 158, 217, 16, 25) # ó
	Crillee15.SetIconLocation(244, pMainTexHandle, 229, 155, 16, 25) # ô
	Crillee15.SetIconLocation(245, pIntlTexHandle,   0,  31, 16, 25) # õ
	Crillee15.SetIconLocation(246, pMainTexHandle,  19, 217, 15, 25) # ö
	Crillee15.SetIconLocation(248, pIntlTexHandle,  17,  31, 16, 25) # ø
	Crillee15.SetIconLocation(249, pMainTexHandle,  70, 217, 16, 25) # ù
	Crillee15.SetIconLocation(250, pMainTexHandle, 175, 217, 16, 25) # ú
	Crillee15.SetIconLocation(251, pMainTexHandle,  53, 217, 16, 25) # û
	Crillee15.SetIconLocation(252, pMainTexHandle, 180, 155, 16, 25) # ü
