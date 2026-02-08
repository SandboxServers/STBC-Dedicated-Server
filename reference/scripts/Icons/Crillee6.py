import App

# Function to load Crillee6 font.
def LoadCrillee6(Crillee6 = None):
	
	if Crillee6 is None:
		# Create font group.
		Crillee6 = App.g_kFontManager.CreateFontGroup("Crillee", 6.0)
		# Add Crillee6 font group to FontManager
		App.g_kFontManager.AddFontGroup(Crillee6)

	# Load font texture
	pTextureHandle = Crillee6.LoadIconTexture('Data/Icons/Crillee6.tga')

	# Set spacing
	Crillee6.SetHorizontalSpacing(0.0)
	Crillee6.SetVerticalSpacing(2.0)
	Crillee6.SetSpaceWidth(5.0)
	Crillee6.SetTabWidth(20.0)

	# Special characters
	Crillee6.SetIconLocation(0,				pTextureHandle,  88, 84,  7, 10) # Box shape
	Crillee6.SetIconLocation(App.WC_CURSOR,	pTextureHandle, 104, 84,  2, 12) # Cursor
	Crillee6.SetIconLocation(App.WC_TAB,	pTextureHandle, 107, 84,  1, 12) # Tab
	Crillee6.SetIconLocation(App.WC_SPACE,	pTextureHandle, 107, 84,  1, 12) # Space

	# Define icon locations
	Crillee6.SetIconLocation( 33, pTextureHandle,   0,   0,  4, 10) # !
	Crillee6.SetIconLocation( 34, pTextureHandle,   5,   0,  4,  6) # "
	Crillee6.SetIconLocation( 35, pTextureHandle,  10,   0,  7, 10) # #
	Crillee6.SetIconLocation( 36, pTextureHandle,  18,   0,  5, 11) # $
	Crillee6.SetIconLocation( 37, pTextureHandle,  24,   0,  9, 10) # %
	Crillee6.SetIconLocation( 38, pTextureHandle,  34,   0,  7, 10) # &
	Crillee6.SetIconLocation( 39, pTextureHandle,  42,   0,  2,  6) # '
	Crillee6.SetIconLocation( 40, pTextureHandle,  45,   0,  4, 11) # (
	Crillee6.SetIconLocation( 41, pTextureHandle,  50,   0,  4, 11) # )
	Crillee6.SetIconLocation( 42, pTextureHandle,  55,   0,  5,  8) # *
	Crillee6.SetIconLocation( 43, pTextureHandle,  61,   0,  6,  9) # +
	Crillee6.SetIconLocation( 44, pTextureHandle,  68,   0,  3, 11) # ,
	Crillee6.SetIconLocation( 45, pTextureHandle,  72,   0,  5,  7) # -
	Crillee6.SetIconLocation( 46, pTextureHandle,  78,   0,  2, 10) # .
	Crillee6.SetIconLocation( 47, pTextureHandle,  81,   0,  7, 10) # /
	Crillee6.SetIconLocation( 48, pTextureHandle,  89,   0,  6, 10) # 0
	Crillee6.SetIconLocation( 49, pTextureHandle,  96,   0,  4, 10) # 1
	Crillee6.SetIconLocation( 50, pTextureHandle, 101,   0,  6, 10) # 2
	Crillee6.SetIconLocation( 51, pTextureHandle, 108,   0,  7, 10) # 3
	Crillee6.SetIconLocation( 52, pTextureHandle, 116,   0,  5, 10) # 4
	Crillee6.SetIconLocation( 53, pTextureHandle, 122,   0,  6, 10) # 5
	Crillee6.SetIconLocation( 54, pTextureHandle,   0,  12,  6, 10) # 6
	Crillee6.SetIconLocation( 55, pTextureHandle,   7,  12,  6, 10) # 7
	Crillee6.SetIconLocation( 56, pTextureHandle,  14,  12,  6, 10) # 8
	Crillee6.SetIconLocation( 57, pTextureHandle,  21,  12,  6, 10) # 9
	Crillee6.SetIconLocation( 58, pTextureHandle,  28,  12,  2, 10) # :
	Crillee6.SetIconLocation( 59, pTextureHandle,  31,  12,  3, 11) # ;
	Crillee6.SetIconLocation( 60, pTextureHandle,  35,  12,  6, 10) # <
	Crillee6.SetIconLocation( 61, pTextureHandle,  42,  12,  6,  9) # =
	Crillee6.SetIconLocation( 62, pTextureHandle,  49,  12,  6, 10) # >
	Crillee6.SetIconLocation( 63, pTextureHandle,  56,  12,  4, 10) # ?
	Crillee6.SetIconLocation( 64, pTextureHandle,  61,  12,  8, 10) # @
	Crillee6.SetIconLocation( 65, pTextureHandle,  70,  12,  8, 10) # A
	Crillee6.SetIconLocation( 66, pTextureHandle,  79,  12,  7, 10) # B
	Crillee6.SetIconLocation( 67, pTextureHandle,  87,  12,  7, 10) # C
	Crillee6.SetIconLocation( 68, pTextureHandle,  96,  12,  8, 10) # D
	Crillee6.SetIconLocation( 69, pTextureHandle, 104,  12,  7, 10) # E
	Crillee6.SetIconLocation( 70, pTextureHandle, 112,  12,  7, 10) # F
	Crillee6.SetIconLocation( 71, pTextureHandle, 120,  12,  7, 10) # G
	Crillee6.SetIconLocation( 72, pTextureHandle,   0,  24,  8, 10) # H
	Crillee6.SetIconLocation( 73, pTextureHandle,   9,  24,  4, 10) # I
	Crillee6.SetIconLocation( 74, pTextureHandle,  14,  24,  6, 10) # J
	Crillee6.SetIconLocation( 75, pTextureHandle,  21,  24,  8, 10) # K
	Crillee6.SetIconLocation( 76, pTextureHandle,  30,  24,  6, 10) # L
	Crillee6.SetIconLocation( 77, pTextureHandle,  37,  24, 10, 10) # M
	Crillee6.SetIconLocation( 78, pTextureHandle,  48,  24,  8, 10) # N
	Crillee6.SetIconLocation( 79, pTextureHandle,  57,  24,  8, 10) # O
	Crillee6.SetIconLocation( 80, pTextureHandle,  66,  24,  7, 10) # P
	Crillee6.SetIconLocation( 81, pTextureHandle,  74,  24,  8, 10) # Q
	Crillee6.SetIconLocation( 82, pTextureHandle,  83,  24,  7, 10) # R
	Crillee6.SetIconLocation( 83, pTextureHandle,  91,  24,  7, 10) # S
	Crillee6.SetIconLocation( 84, pTextureHandle,  99,  24,  7, 10) # T
	Crillee6.SetIconLocation( 85, pTextureHandle, 107,  24,  7, 10) # U
	Crillee6.SetIconLocation( 86, pTextureHandle, 115,  24,  7, 10) # V
	Crillee6.SetIconLocation( 87, pTextureHandle,   0,  36, 11, 10) # W
	Crillee6.SetIconLocation( 88, pTextureHandle,  12,  36,  7, 10) # X
	Crillee6.SetIconLocation( 89, pTextureHandle,  20,  36,  7, 10) # Y
	Crillee6.SetIconLocation( 90, pTextureHandle,  28,  36,  8, 10) # Z
	Crillee6.SetIconLocation( 91, pTextureHandle,  37,  36,  5, 11) # [
	Crillee6.SetIconLocation( 92, pTextureHandle,  43,  36,  4, 10) # \
	Crillee6.SetIconLocation( 93, pTextureHandle,  48,  36,  5, 11) # ]
	Crillee6.SetIconLocation( 94, pTextureHandle,  54,  36,  5,  6) # ^
	Crillee6.SetIconLocation( 95, pTextureHandle,  60,  36,  6, 11) # _
	Crillee6.SetIconLocation( 96, pTextureHandle,  67,  36,  3,  4) # `
	Crillee6.SetIconLocation( 97, pTextureHandle,  71,  36,  6, 10) # a
	Crillee6.SetIconLocation( 98, pTextureHandle,  78,  36,  7, 10) # b
	Crillee6.SetIconLocation( 99, pTextureHandle,  86,  36,  6, 10) # c
	Crillee6.SetIconLocation(100, pTextureHandle,  93,  36,  7, 10) # d
	Crillee6.SetIconLocation(101, pTextureHandle, 101,  36,  7, 10) # e
	Crillee6.SetIconLocation(102, pTextureHandle, 109,  36,  5, 11) # f
	Crillee6.SetIconLocation(103, pTextureHandle, 115,  36,  7, 12) # g
	Crillee6.SetIconLocation(104, pTextureHandle,   0,  48,  7, 10) # h
	Crillee6.SetIconLocation(105, pTextureHandle,   8,  48,  4, 10) # i
	Crillee6.SetIconLocation(106, pTextureHandle,  13,  48,  5, 12) # j
	Crillee6.SetIconLocation(107, pTextureHandle,  20,  48,  6, 10) # k
	Crillee6.SetIconLocation(108, pTextureHandle,  27,  48,  4, 10) # l
	Crillee6.SetIconLocation(109, pTextureHandle,  33,  48,  9, 10) # m
	Crillee6.SetIconLocation(110, pTextureHandle,  43,  48,  7, 10) # n
	Crillee6.SetIconLocation(111, pTextureHandle,  51,  48,  7, 10) # o
	Crillee6.SetIconLocation(112, pTextureHandle,  59,  48,  7, 12) # p
	Crillee6.SetIconLocation(113, pTextureHandle,  67,  48,  7, 12) # q
	Crillee6.SetIconLocation(114, pTextureHandle,  75,  48,  6, 10) # r
	Crillee6.SetIconLocation(115, pTextureHandle,  82,  48,  6, 10) # s
	Crillee6.SetIconLocation(116, pTextureHandle,  89,  48,  5, 10) # t
	Crillee6.SetIconLocation(117, pTextureHandle,  95,  48,  6, 10) # u
	Crillee6.SetIconLocation(118, pTextureHandle, 102,  48,  5, 10) # v
	Crillee6.SetIconLocation(119, pTextureHandle, 108,  48,  8, 10) # w
	Crillee6.SetIconLocation(120, pTextureHandle, 117,  48,  6, 10) # x
	Crillee6.SetIconLocation(121, pTextureHandle,   0,  60,  6, 12) # y
	Crillee6.SetIconLocation(122, pTextureHandle,   7,  60,  6, 10) # z
	Crillee6.SetIconLocation(123, pTextureHandle,  15,  60,  4, 11) # {
	Crillee6.SetIconLocation(124, pTextureHandle,  20,  60,  3, 12) # |
	Crillee6.SetIconLocation(125, pTextureHandle,  24,  60,  4, 11) # }
	Crillee6.SetIconLocation(126, pTextureHandle,  29,  60,  6,  8) # ~

	Crillee6.SetIconLocation(132, pTextureHandle,   5,   0,  4, 12, App.TGIconGroup.ROTATE_180) # " (upsidedown ")
	Crillee6.SetIconLocation(161, pTextureHandle,   0,   0,  4, 12, App.TGIconGroup.ROTATE_180) # ¡ (upsidedown !)
	Crillee6.SetIconLocation(162, pTextureHandle,   0,  84,  7, 11) # ¢
	Crillee6.SetIconLocation(163, pTextureHandle,   8,  84,  6, 10) # £
	Crillee6.SetIconLocation(165, pTextureHandle,  15,  84,  6, 10) # ¥
	Crillee6.SetIconLocation(169, pTextureHandle, 109,  84, 10, 10) # ©
	Crillee6.SetIconLocation(180, pTextureHandle,  67,  36,  3,  4, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_HORIZONTAL) # ´
	Crillee6.SetIconLocation(191, pTextureHandle,  83,  84,  4, 10) # ¿
	Crillee6.SetIconLocation(192, pTextureHandle,  22,  84,  8, 10) # À
	Crillee6.SetIconLocation(193, pTextureHandle,   0,  96,  8, 10) # Á
	Crillee6.SetIconLocation(194, pTextureHandle,   9,  96,  8, 10) # Â
	Crillee6.SetIconLocation(195, pTextureHandle,  18,  96,  8, 10) # Ã
	Crillee6.SetIconLocation(196, pTextureHandle,  11,  72,  8, 10) # Ä
	Crillee6.SetIconLocation(197, pTextureHandle,  20,  72,  8, 10) # Å
	Crillee6.SetIconLocation(198, pTextureHandle,  48,  72, 11, 10) # Æ
	Crillee6.SetIconLocation(199, pTextureHandle,  36,  60,  7, 12) # Ç
	Crillee6.SetIconLocation(200, pTextureHandle,  31,  84,  7, 10) # È
	Crillee6.SetIconLocation(201, pTextureHandle,  29,  72,  7, 10) # É
	Crillee6.SetIconLocation(202, pTextureHandle,  27,  96,  7, 10) # Ê
	Crillee6.SetIconLocation(203, pTextureHandle,  35,  96,  7, 10) # Ë
	Crillee6.SetIconLocation(204, pTextureHandle, 123,  72,  4, 10) # Ì
	Crillee6.SetIconLocation(205, pTextureHandle,  43,  96,  4, 10) # Í
	Crillee6.SetIconLocation(206, pTextureHandle,  48,  96,  5, 10) # Î
	Crillee6.SetIconLocation(207, pTextureHandle,  54,  96,  5, 10) # Ï
	Crillee6.SetIconLocation(209, pTextureHandle,  74,  84,  8, 10) # Ñ
	Crillee6.SetIconLocation(210, pTextureHandle,  60,  96,  8, 10) # Ò
	Crillee6.SetIconLocation(211, pTextureHandle,  69,  96,  8, 10) # Ó
	Crillee6.SetIconLocation(212, pTextureHandle,  60,  72,  8, 10) # Ô
	Crillee6.SetIconLocation(213, pTextureHandle,  78,  96,  8, 10) # Õ
	Crillee6.SetIconLocation(214, pTextureHandle, 106,  72,  8, 10) # Ö
	Crillee6.SetIconLocation(216, pTextureHandle,  87,  96,  8, 10) # Ø
	Crillee6.SetIconLocation(217, pTextureHandle,  96,  96,  7, 10) # Ù
	Crillee6.SetIconLocation(218, pTextureHandle, 104,  96,  7, 10) # Ú
	Crillee6.SetIconLocation(219, pTextureHandle, 112,  96,  7, 10) # Û
	Crillee6.SetIconLocation(220, pTextureHandle, 115,  72,  7, 10) # Ü
	Crillee6.SetIconLocation(221, pTextureHandle, 120,  84,  7, 10) # Ý
	Crillee6.SetIconLocation(223, pTextureHandle,  96,  84,  7, 12) # ß
	Crillee6.SetIconLocation(224, pTextureHandle,  73,  60,  6, 10) # à
	Crillee6.SetIconLocation(225, pTextureHandle,  39,  84,  6, 10) # á
	Crillee6.SetIconLocation(226, pTextureHandle,  59,  60,  6, 10) # â
	Crillee6.SetIconLocation(227, pTextureHandle,   0, 108,  6, 10) # ã
	Crillee6.SetIconLocation(228, pTextureHandle,  66,  60,  7, 10) # ä
	Crillee6.SetIconLocation(229, pTextureHandle,  80,  60,  6, 10) # å
	Crillee6.SetIconLocation(230, pTextureHandle,  37,  72, 10, 10) # æ
	Crillee6.SetIconLocation(231, pTextureHandle,  87,  60,  7, 10) # ç
	Crillee6.SetIconLocation(232, pTextureHandle, 111,  60,  7, 10) # è
	Crillee6.SetIconLocation(233, pTextureHandle,  51,  60,  7, 10) # é
	Crillee6.SetIconLocation(234, pTextureHandle,  95,  60,  7, 10) # ê
	Crillee6.SetIconLocation(235, pTextureHandle, 103,  60,  7, 10) # ë
	Crillee6.SetIconLocation(236, pTextureHandle,   6,  72,  4, 10) # ì
	Crillee6.SetIconLocation(237, pTextureHandle,  46,  84,  4, 10) # í
	Crillee6.SetIconLocation(238, pTextureHandle,   0,  72,  5, 10) # î
	Crillee6.SetIconLocation(239, pTextureHandle, 119,  60,  5, 10) # ï
	Crillee6.SetIconLocation(241, pTextureHandle,  66,  84,  7, 10) # ñ
	Crillee6.SetIconLocation(242, pTextureHandle,  77,  72,  7, 10) # ò
	Crillee6.SetIconLocation(243, pTextureHandle,  51,  84,  7, 10) # ó
	Crillee6.SetIconLocation(244, pTextureHandle, 120,  96,  7, 10) # ô
	Crillee6.SetIconLocation(245, pTextureHandle,   7, 108,  7, 10) # õ
	Crillee6.SetIconLocation(246, pTextureHandle,  69,  72,  7, 10) # ö
	Crillee6.SetIconLocation(248, pTextureHandle,  15, 108,  7, 10) # ø
	Crillee6.SetIconLocation(249, pTextureHandle,  92,  72,  6, 10) # ù
	Crillee6.SetIconLocation(250, pTextureHandle,  59,  84,  6, 10) # ú
	Crillee6.SetIconLocation(251, pTextureHandle,  85,  72,  6, 10) # û
	Crillee6.SetIconLocation(252, pTextureHandle,  44,  60,  6, 10) # ü
