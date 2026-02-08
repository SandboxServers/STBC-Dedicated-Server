import App

# Function to load Crillee5 font.
def LoadCrillee5(Crillee5 = None):
	
	if Crillee5 is None:
		# Create font group.
		Crillee5 = App.g_kFontManager.CreateFontGroup("Crillee", 5.0)
		# Add Crillee5 font group to FontManager
		App.g_kFontManager.AddFontGroup(Crillee5)

	# Load font texture
	pTextureHandle = Crillee5.LoadIconTexture('Data/Icons/Crillee5.tga')

	# Set spacing
	Crillee5.SetHorizontalSpacing(0.0)
	Crillee5.SetVerticalSpacing(2.0)
	Crillee5.SetSpaceWidth(4.0)
	Crillee5.SetTabWidth(16.0)

	# Special characters
	Crillee5.SetIconLocation(0,				pTextureHandle,  68, 72,  6,  9) # Box shape
	Crillee5.SetIconLocation(App.WC_CURSOR,	pTextureHandle,  64, 72,  1, 11) # Cursor
	Crillee5.SetIconLocation(App.WC_TAB,	pTextureHandle,  66, 72,  1, 11) # Tab
	Crillee5.SetIconLocation(App.WC_SPACE,	pTextureHandle,  66, 72,  1, 11) # Space

	# Define icon locations
	Crillee5.SetIconLocation( 33, pTextureHandle,   0,   0,  3,  9) # !
	Crillee5.SetIconLocation( 34, pTextureHandle,   4,   0,  3,  5) # "
	Crillee5.SetIconLocation( 35, pTextureHandle,   8,   0,  7,  9) # #
	Crillee5.SetIconLocation( 36, pTextureHandle,  16,   0,  5, 10) # $
	Crillee5.SetIconLocation( 37, pTextureHandle,  22,   0,  7,  9) # %
	Crillee5.SetIconLocation( 38, pTextureHandle,  30,   0,  5,  9) # &
	Crillee5.SetIconLocation( 39, pTextureHandle,  36,   0,  1,  5) # '
	Crillee5.SetIconLocation( 40, pTextureHandle,  38,   0,  3, 10) # (
	Crillee5.SetIconLocation( 41, pTextureHandle,  42,   0,  3, 10) # )
	Crillee5.SetIconLocation( 42, pTextureHandle,  46,   0,  3,  6) # *
	Crillee5.SetIconLocation( 43, pTextureHandle,  50,   0,  4,  9) # +
	Crillee5.SetIconLocation( 44, pTextureHandle,  55,   0,  2, 10) # ,
	Crillee5.SetIconLocation( 45, pTextureHandle,  58,   0,  3,  7) # -
	Crillee5.SetIconLocation( 46, pTextureHandle,  62,   0,  2,  9) # .
	Crillee5.SetIconLocation( 47, pTextureHandle,  65,   0,  5,  9) # /
	Crillee5.SetIconLocation( 48, pTextureHandle,  71,   0,  5,  9) # 0
	Crillee5.SetIconLocation( 49, pTextureHandle,  77,   0,  3,  9) # 1
	Crillee5.SetIconLocation( 50, pTextureHandle,  81,   0,  6,  9) # 2
	Crillee5.SetIconLocation( 51, pTextureHandle,  88,   0,  5, 10) # 3
	Crillee5.SetIconLocation( 52, pTextureHandle,  94,   0,  5,  9) # 4
	Crillee5.SetIconLocation( 53, pTextureHandle, 100,   0,  5, 10) # 5
	Crillee5.SetIconLocation( 54, pTextureHandle, 106,   0,  5, 10) # 6
	Crillee5.SetIconLocation( 55, pTextureHandle, 112,   0,  5,  9) # 7
	Crillee5.SetIconLocation( 56, pTextureHandle, 118,   0,  5,  9) # 8
	Crillee5.SetIconLocation( 57, pTextureHandle,   0,  12,  5,  9) # 9
	Crillee5.SetIconLocation( 58, pTextureHandle,   6,  12,  2,  9) # :
	Crillee5.SetIconLocation( 59, pTextureHandle,   9,  12,  2, 10) # ;
	Crillee5.SetIconLocation( 60, pTextureHandle,  12,  12,  5,  9) # <
	Crillee5.SetIconLocation( 61, pTextureHandle,  18,  12,  5,  8) # =
	Crillee5.SetIconLocation( 62, pTextureHandle,  24,  12,  5,  9) # >
	Crillee5.SetIconLocation( 63, pTextureHandle,  30,  12,  4,  9) # ?
	Crillee5.SetIconLocation( 64, pTextureHandle,  35,  12,  7,  9) # @
	Crillee5.SetIconLocation( 65, pTextureHandle,  43,  12,  6,  9) # A
	Crillee5.SetIconLocation( 66, pTextureHandle,  50,  12,  7,  9) # B
	Crillee5.SetIconLocation( 67, pTextureHandle,  58,  12,  6,  9) # C
	Crillee5.SetIconLocation( 68, pTextureHandle,  65,  12,  6,  9) # D
	Crillee5.SetIconLocation( 69, pTextureHandle,  72,  12,  6,  9) # E
	Crillee5.SetIconLocation( 70, pTextureHandle,  79,  12,  6,  9) # F
	Crillee5.SetIconLocation( 71, pTextureHandle,  86,  12,  6,  9) # G
	Crillee5.SetIconLocation( 72, pTextureHandle,  93,  12,  7,  9) # H
	Crillee5.SetIconLocation( 73, pTextureHandle, 101,  12,  4,  9) # I
	Crillee5.SetIconLocation( 74, pTextureHandle, 106,  12,  4,  9) # J
	Crillee5.SetIconLocation( 75, pTextureHandle, 111,  12,  7,  9) # K
	Crillee5.SetIconLocation( 76, pTextureHandle, 119,  12,  5,  9) # L
	Crillee5.SetIconLocation( 77, pTextureHandle,   0,  24,  7,  9) # M
	Crillee5.SetIconLocation( 78, pTextureHandle,   8,  24,  6,  9) # N
	Crillee5.SetIconLocation( 79, pTextureHandle,  15,  24,  6,  9) # O
	Crillee5.SetIconLocation( 80, pTextureHandle,  22,  24,  6,  9) # P
	Crillee5.SetIconLocation( 81, pTextureHandle,  29,  24,  6, 10) # Q
	Crillee5.SetIconLocation( 82, pTextureHandle,  36,  24,  6,  9) # R
	Crillee5.SetIconLocation( 83, pTextureHandle,  43,  24,  6,  9) # S
	Crillee5.SetIconLocation( 84, pTextureHandle,  50,  24,  5,  9) # T
	Crillee5.SetIconLocation( 85, pTextureHandle,  56,  24,  6,  9) # U
	Crillee5.SetIconLocation( 86, pTextureHandle,  63,  24,  6,  9) # V
	Crillee5.SetIconLocation( 87, pTextureHandle,  70,  24,  8,  9) # W
	Crillee5.SetIconLocation( 88, pTextureHandle,  79,  24,  6,  9) # X
	Crillee5.SetIconLocation( 89, pTextureHandle,  86,  24,  6,  9) # Y
	Crillee5.SetIconLocation( 90, pTextureHandle,  93,  24,  6,  9) # Z
	Crillee5.SetIconLocation( 91, pTextureHandle, 100,  24,  3, 10) # [
	Crillee5.SetIconLocation( 92, pTextureHandle, 104,  24,  4,  9) # \
	Crillee5.SetIconLocation( 93, pTextureHandle, 109,  24,  3, 10) # ]
	Crillee5.SetIconLocation( 94, pTextureHandle, 113,  24,  5,  6) # ^
	Crillee5.SetIconLocation( 95, pTextureHandle, 119,  24,  5,  9) # _
	Crillee5.SetIconLocation( 96, pTextureHandle,   0,  36,  2,  3) # `
	Crillee5.SetIconLocation( 97, pTextureHandle,   3,  36,  6,  9) # a
	Crillee5.SetIconLocation( 98, pTextureHandle,  10,  36,  5,  9) # b
	Crillee5.SetIconLocation( 99, pTextureHandle,  16,  36,  5,  9) # c
	Crillee5.SetIconLocation(100, pTextureHandle,  22,  36,  5,  9) # d
	Crillee5.SetIconLocation(101, pTextureHandle,  28,  36,  5,  9) # e
	Crillee5.SetIconLocation(102, pTextureHandle,  34,  36,  5,  9) # f
	Crillee5.SetIconLocation(103, pTextureHandle,  40,  36,  5, 11) # g
	Crillee5.SetIconLocation(104, pTextureHandle,  46,  36,  5,  9) # h
	Crillee5.SetIconLocation(105, pTextureHandle,  52,  36,  3,  9) # i
	Crillee5.SetIconLocation(106, pTextureHandle,  56,  36,  4, 11) # j
	Crillee5.SetIconLocation(107, pTextureHandle,  61,  36,  5,  9) # k
	Crillee5.SetIconLocation(108, pTextureHandle,  67,  36,  3,  9) # l
	Crillee5.SetIconLocation(109, pTextureHandle,  71,  36,  8,  9) # m
	Crillee5.SetIconLocation(110, pTextureHandle,  80,  36,  5,  9) # n
	Crillee5.SetIconLocation(111, pTextureHandle,  86,  36,  5,  9) # o
	Crillee5.SetIconLocation(112, pTextureHandle,  92,  36,  5, 11) # p
	Crillee5.SetIconLocation(113, pTextureHandle,  98,  36,  6, 11) # q
	Crillee5.SetIconLocation(114, pTextureHandle, 105,  36,  4,  9) # r
	Crillee5.SetIconLocation(115, pTextureHandle, 110,  36,  5,  9) # s
	Crillee5.SetIconLocation(116, pTextureHandle, 116,  36,  4,  9) # t
	Crillee5.SetIconLocation(117, pTextureHandle, 121,  36,  5,  9) # u
	Crillee5.SetIconLocation(118, pTextureHandle,   0,  48,  5,  9) # v
	Crillee5.SetIconLocation(119, pTextureHandle,   6,  48,  7,  9) # w
	Crillee5.SetIconLocation(120, pTextureHandle,  14,  48,  6,  9) # x
	Crillee5.SetIconLocation(121, pTextureHandle,  21,  48,  5, 11) # y
	Crillee5.SetIconLocation(122, pTextureHandle,  27,  48,  5,  9) # z
	Crillee5.SetIconLocation(123, pTextureHandle,  33,  48,  4, 10) # {
	Crillee5.SetIconLocation(124, pTextureHandle,  38,  48,  3, 10) # |
	Crillee5.SetIconLocation(125, pTextureHandle,  42,  48,  4, 10) # }
	Crillee5.SetIconLocation(126, pTextureHandle,  47,  48,  5,  7) # ~

	Crillee5.SetIconLocation(132, pTextureHandle,   4,   0,  3, 11, App.TGIconGroup.ROTATE_180) # " (upsidedown ")
	Crillee5.SetIconLocation(161, pTextureHandle,   0,   0,  3, 11, App.TGIconGroup.ROTATE_180) # ¡ (upsidedown !)
	Crillee5.SetIconLocation(162, pTextureHandle, 106,  60,  5, 11) # ¢
	Crillee5.SetIconLocation(163, pTextureHandle, 112,  60,  5, 10) # £
	Crillee5.SetIconLocation(165, pTextureHandle, 118,  60,  6,  9) # ¥
	Crillee5.SetIconLocation(169, pTextureHandle,  75,  72,  9,  9) # ©
	Crillee5.SetIconLocation(180, pTextureHandle,   0,  36,  2,  3, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_HORIZONTAL) # ´
	Crillee5.SetIconLocation(191, pTextureHandle,  51,  72,  4,  9) # ¿
	Crillee5.SetIconLocation(192, pTextureHandle,   0,  72,  6,  9) # À
	Crillee5.SetIconLocation(193, pTextureHandle,   7,  72,  6,  9) # Á
	Crillee5.SetIconLocation(194, pTextureHandle,  85,  72,  6,  9) # Â
	Crillee5.SetIconLocation(195, pTextureHandle,  92,  72,  6,  9) # Ã
	Crillee5.SetIconLocation(196, pTextureHandle,  14,  60,  6,  9) # Ä
	Crillee5.SetIconLocation(197, pTextureHandle,  21,  60,  6,  9) # Å
	Crillee5.SetIconLocation(198, pTextureHandle,  44,  60, 10,  9) # Æ
	Crillee5.SetIconLocation(199, pTextureHandle,  53,  48,  6, 11) # Ç
	Crillee5.SetIconLocation(200, pTextureHandle,  99,  72,  6,  9) # È
	Crillee5.SetIconLocation(201, pTextureHandle,  28,  60,  6,  9) # É
	Crillee5.SetIconLocation(202, pTextureHandle, 106,  72,  6,  9) # Ê
	Crillee5.SetIconLocation(203, pTextureHandle, 113,  72,  6,  9) # Ë
	Crillee5.SetIconLocation(204, pTextureHandle, 120 , 72,  4,  9) # Ì
	Crillee5.SetIconLocation(205, pTextureHandle,   0,  84,  4,  9) # Í
	Crillee5.SetIconLocation(206, pTextureHandle,   5,  84,  4,  9) # Î
	Crillee5.SetIconLocation(207, pTextureHandle,  10,  84,  4,  9) # Ï
	Crillee5.SetIconLocation(209, pTextureHandle,  44,  72,  6,  9) # Ñ
	Crillee5.SetIconLocation(210, pTextureHandle,  15,  84,  6,  9) # Ò
	Crillee5.SetIconLocation(211, pTextureHandle,  22,  84,  6,  9) # Ó
	Crillee5.SetIconLocation(212, pTextureHandle,  55,  60,  6,  9) # Ô
	Crillee5.SetIconLocation(213, pTextureHandle,  29,  84,  6,  9) # Õ
	Crillee5.SetIconLocation(214, pTextureHandle,  92,  60,  6,  9) # Ö
	Crillee5.SetIconLocation(216, pTextureHandle,  36,  84,  6,  9) # Ø
	Crillee5.SetIconLocation(217, pTextureHandle,  43,  84,  6,  9) # Ù
	Crillee5.SetIconLocation(218, pTextureHandle,  50,  84,  6,  9) # Ú
	Crillee5.SetIconLocation(219, pTextureHandle,  57,  84,  6,  9) # Û
	Crillee5.SetIconLocation(220, pTextureHandle,  99,  60,  6,  9) # Ü
	Crillee5.SetIconLocation(221, pTextureHandle,  64,  84,  6,  9) # Ý
	Crillee5.SetIconLocation(223, pTextureHandle,  56,  72,  7, 11) # ß
	Crillee5.SetIconLocation(224, pTextureHandle,  86,  48,  6,  9) # à
	Crillee5.SetIconLocation(225, pTextureHandle,  14,  72,  6,  9) # á
	Crillee5.SetIconLocation(226, pTextureHandle,  72,  48,  6,  9) # â
	Crillee5.SetIconLocation(227, pTextureHandle,  71,  84,  6,  9) # ã
	Crillee5.SetIconLocation(228, pTextureHandle,  79,  48,  6,  9) # ä
	Crillee5.SetIconLocation(229, pTextureHandle,  93,  48,  6,  9) # å
	Crillee5.SetIconLocation(230, pTextureHandle,  35,  60,  8,  9) # æ
	Crillee5.SetIconLocation(231, pTextureHandle, 100,  48,  5, 11) # ç
	Crillee5.SetIconLocation(232, pTextureHandle, 118,  48,  5,  9) # è
	Crillee5.SetIconLocation(233, pTextureHandle,  66,  48,  5,  9) # é
	Crillee5.SetIconLocation(234, pTextureHandle, 106,  48,  5,  9) # ê
	Crillee5.SetIconLocation(235, pTextureHandle, 112,  48,  5,  9) # ë
	Crillee5.SetIconLocation(236, pTextureHandle,  10,  60,  3,  9) # ì
	Crillee5.SetIconLocation(237, pTextureHandle,  21,  72,  4,  9) # í
	Crillee5.SetIconLocation(238, pTextureHandle,   5,  60,  4,  9) # î
	Crillee5.SetIconLocation(239, pTextureHandle,   0,  60,  4,  9) # ï
	Crillee5.SetIconLocation(241, pTextureHandle,  38,  72,  5,  9) # ñ
	Crillee5.SetIconLocation(242, pTextureHandle,  68,  60,  5,  9) # ò
	Crillee5.SetIconLocation(243, pTextureHandle,  26,  72,  5,  9) # ó
	Crillee5.SetIconLocation(244, pTextureHandle,  78,  84,  5,  9) # ô
	Crillee5.SetIconLocation(245, pTextureHandle,  84,  84,  5,  9) # õ
	Crillee5.SetIconLocation(246, pTextureHandle,  62,  60,  5,  9) # ö
	Crillee5.SetIconLocation(248, pTextureHandle,  90,  84,  5,  9) # ø
	Crillee5.SetIconLocation(249, pTextureHandle,  80,  60,  5,  9) # ù
	Crillee5.SetIconLocation(250, pTextureHandle,  32,  72,  5,  9) # ú
	Crillee5.SetIconLocation(251, pTextureHandle,  74,  60,  5,  9) # û
	Crillee5.SetIconLocation(252, pTextureHandle,  60,  48,  5,  9) # ü
