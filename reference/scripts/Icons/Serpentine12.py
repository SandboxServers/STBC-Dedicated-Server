import App

# Function to load Serpentine12 font.
def LoadSerpentine12(Serpentine12 = None):
	
	if Serpentine12 is None:
		# Create font group.
		Serpentine12 = App.g_kFontManager.CreateFontGroup("Serpentine", 12.0)
		# Add Serpentine12 font group to FontManager
		App.g_kFontManager.AddFontGroup(Serpentine12)

	# Load font texture
	pTextureHandle = Serpentine12.LoadIconTexture("Data/Icons/Serpentine12.tga")

	# Set spacing
	Serpentine12.SetHorizontalSpacing(2.0)
	Serpentine12.SetVerticalSpacing(2.0)
	Serpentine12.SetSpaceWidth(8.0)
	Serpentine12.SetTabWidth(32.0)

	# Special characters
	Serpentine12.SetIconLocation(0,				pTextureHandle,   0, 110, 11, 17) # Box shape
	Serpentine12.SetIconLocation(App.WC_CURSOR,	pTextureHandle, 245,  44,  1, 22) # Cursor
	Serpentine12.SetIconLocation(App.WC_TAB,	pTextureHandle, 247,  44,  1, 22) # Tab
	Serpentine12.SetIconLocation(App.WC_SPACE,	pTextureHandle, 247,  44,  1, 22) # Space

	Serpentine12.SetIconLocation(  0, pTextureHandle, 245,  44,  1, 22) # Cursor
	Serpentine12.SetIconLocation(  9, pTextureHandle, 247,  44,  1, 10) # Tab
	Serpentine12.SetIconLocation( 32, pTextureHandle, 247,  44,  1, 10) # Space

	# Define icon locations
	Serpentine12.SetIconLocation( 33, pTextureHandle,   0,   0,  6, 17) # !
	Serpentine12.SetIconLocation( 34, pTextureHandle,   7,   0,  6, 10) # "
	Serpentine12.SetIconLocation( 35, pTextureHandle,  14,   0, 10, 17) # #
	Serpentine12.SetIconLocation( 36, pTextureHandle,  25,   0, 13, 18) # $
	Serpentine12.SetIconLocation( 37, pTextureHandle,  39,   0, 19, 17) # %
	Serpentine12.SetIconLocation( 38, pTextureHandle,  59,   0, 16, 17) # &
	Serpentine12.SetIconLocation( 39, pTextureHandle,  77,   0,  3, 10) # '
	Serpentine12.SetIconLocation( 40, pTextureHandle,  81,   0,  8, 18) # (
	Serpentine12.SetIconLocation( 41, pTextureHandle,  90,   0,  8, 18) # )
	Serpentine12.SetIconLocation( 42, pTextureHandle,  99,   0,  9, 12) # *
	Serpentine12.SetIconLocation( 43, pTextureHandle, 109,   0, 10, 17) # +
	Serpentine12.SetIconLocation( 44, pTextureHandle, 120,   0,  5, 20) # ,
	Serpentine12.SetIconLocation( 45, pTextureHandle, 127,   0,  8, 14) # -
	Serpentine12.SetIconLocation( 46, pTextureHandle, 136,   0,  6, 17) # .
	Serpentine12.SetIconLocation( 47, pTextureHandle, 143,   0,  7, 17) # /
	Serpentine12.SetIconLocation( 48, pTextureHandle, 151,   0, 15, 17) # 0
	Serpentine12.SetIconLocation( 49, pTextureHandle, 167,   0,  7, 17) # 1
	Serpentine12.SetIconLocation( 50, pTextureHandle, 175,   0, 14, 17) # 2
	Serpentine12.SetIconLocation( 51, pTextureHandle, 190,   0, 14, 17) # 3
	Serpentine12.SetIconLocation( 52, pTextureHandle, 205,   0, 16, 17) # 4
	Serpentine12.SetIconLocation( 53, pTextureHandle, 222,   0, 14, 17) # 5
	Serpentine12.SetIconLocation( 54, pTextureHandle, 237,   0, 15, 17) # 6
	Serpentine12.SetIconLocation( 55, pTextureHandle,   0,  22, 14, 17) # 7
	Serpentine12.SetIconLocation( 56, pTextureHandle,  15,  22, 14, 17) # 8
	Serpentine12.SetIconLocation( 57, pTextureHandle,  30,  22, 14, 17) # 9
	Serpentine12.SetIconLocation( 58, pTextureHandle,  45,  22,  5, 17) # :
	Serpentine12.SetIconLocation( 59, pTextureHandle,  51,  22,  6, 20) # ;
	Serpentine12.SetIconLocation( 60, pTextureHandle,  58,  22, 11, 17) # <
	Serpentine12.SetIconLocation( 61, pTextureHandle,  70,  22, 10, 15) # =
	Serpentine12.SetIconLocation( 62, pTextureHandle,  81,  22, 10, 17) # >
	Serpentine12.SetIconLocation( 63, pTextureHandle,  92,  22, 13, 17) # ?
	Serpentine12.SetIconLocation( 64, pTextureHandle, 106,  22, 13, 17) # @
	Serpentine12.SetIconLocation( 65, pTextureHandle, 120,  22, 17, 17) # A
	Serpentine12.SetIconLocation( 66, pTextureHandle, 138,  22, 14, 17) # B
	Serpentine12.SetIconLocation( 67, pTextureHandle, 153,  22, 12, 17) # C
	Serpentine12.SetIconLocation( 68, pTextureHandle, 166,  22, 14, 17) # D
	Serpentine12.SetIconLocation( 69, pTextureHandle, 181,  22, 11, 17) # E
	Serpentine12.SetIconLocation( 70, pTextureHandle, 193,  22, 11, 17) # F
	Serpentine12.SetIconLocation( 71, pTextureHandle, 205,  22, 14, 17) # G
	Serpentine12.SetIconLocation( 72, pTextureHandle, 220,  22, 14, 17) # H
	Serpentine12.SetIconLocation( 73, pTextureHandle, 235,  22,  6, 17) # I
	Serpentine12.SetIconLocation( 74, pTextureHandle, 242,  22, 11, 17) # J
	Serpentine12.SetIconLocation( 75, pTextureHandle,   0,  44, 15, 17) # K
	Serpentine12.SetIconLocation( 76, pTextureHandle,  16,  44, 12, 17) # L
	Serpentine12.SetIconLocation( 77, pTextureHandle,  29,  44, 18, 17) # M
	Serpentine12.SetIconLocation( 78, pTextureHandle,  48,  44, 15, 17) # N
	Serpentine12.SetIconLocation( 79, pTextureHandle,  64,  44, 15, 17) # O
	Serpentine12.SetIconLocation( 80, pTextureHandle,  80,  44, 14, 17) # P
	Serpentine12.SetIconLocation( 81, pTextureHandle,  95,  44, 15, 19) # Q
	Serpentine12.SetIconLocation( 82, pTextureHandle, 111,  44, 15, 17) # R
	Serpentine12.SetIconLocation( 83, pTextureHandle, 127,  44, 13, 17) # S
	Serpentine12.SetIconLocation( 84, pTextureHandle, 141,  44, 13, 17) # T
	Serpentine12.SetIconLocation( 85, pTextureHandle, 155,  44, 15, 17) # U
	Serpentine12.SetIconLocation( 86, pTextureHandle, 171,  44, 16, 17) # V
	Serpentine12.SetIconLocation( 87, pTextureHandle, 188,  44, 22, 17) # W
	Serpentine12.SetIconLocation( 88, pTextureHandle, 211,  44, 16, 17) # X
	Serpentine12.SetIconLocation( 89, pTextureHandle, 228,  44, 16, 17) # Y
	Serpentine12.SetIconLocation( 90, pTextureHandle,   0,  66, 14, 17) # Z
	Serpentine12.SetIconLocation( 91, pTextureHandle,  15,  66,  7, 18) # [
	Serpentine12.SetIconLocation( 92, pTextureHandle,  23,  66,  7, 17) # \
	Serpentine12.SetIconLocation( 93, pTextureHandle,  31,  66,  7, 18) # ]
	Serpentine12.SetIconLocation( 94, pTextureHandle,  39,  66,  9, 11) # ^
	Serpentine12.SetIconLocation( 95, pTextureHandle,  49,  66, 11, 19) # _
	Serpentine12.SetIconLocation( 96, pTextureHandle,  61,  66,  6,  6) # `
	Serpentine12.SetIconLocation( 97, pTextureHandle,  68,  66, 13, 17) # a
	Serpentine12.SetIconLocation( 98, pTextureHandle,  82,  66, 13, 17) # b
	Serpentine12.SetIconLocation( 99, pTextureHandle,  96,  66, 12, 17) # c
	Serpentine12.SetIconLocation(100, pTextureHandle, 109,  66, 13, 17) # d
	Serpentine12.SetIconLocation(101, pTextureHandle, 123,  66, 13, 17) # e
	Serpentine12.SetIconLocation(102, pTextureHandle, 137,  66, 11, 17) # f
	Serpentine12.SetIconLocation(103, pTextureHandle, 149,  66, 14, 20) # g
	Serpentine12.SetIconLocation(104, pTextureHandle, 164,  66, 14, 17) # h
	Serpentine12.SetIconLocation(105, pTextureHandle, 179,  66,  6, 17) # i
	Serpentine12.SetIconLocation(106, pTextureHandle, 186,  66, 10, 21) # j
	Serpentine12.SetIconLocation(107, pTextureHandle, 197,  66, 14, 17) # k
	Serpentine12.SetIconLocation(108, pTextureHandle, 212,  66,  6, 17) # l
	Serpentine12.SetIconLocation(109, pTextureHandle, 219,  66, 20, 17) # m
	Serpentine12.SetIconLocation(110, pTextureHandle, 240,  66, 14, 17) # n
	Serpentine12.SetIconLocation(111, pTextureHandle,   0,  88, 14, 17) # o
	Serpentine12.SetIconLocation(112, pTextureHandle,  15,  88, 14, 21) # p
	Serpentine12.SetIconLocation(113, pTextureHandle,  30,  88, 13, 21) # q
	Serpentine12.SetIconLocation(114, pTextureHandle,  44,  88, 10, 17) # r
	Serpentine12.SetIconLocation(115, pTextureHandle,  55,  88, 13, 17) # s
	Serpentine12.SetIconLocation(116, pTextureHandle,  69,  88, 12, 17) # t
	Serpentine12.SetIconLocation(117, pTextureHandle,  82,  88, 14, 17) # u
	Serpentine12.SetIconLocation(118, pTextureHandle,  97,  88, 14, 17) # v
	Serpentine12.SetIconLocation(119, pTextureHandle, 112,  88, 19, 17) # w
	Serpentine12.SetIconLocation(120, pTextureHandle, 132,  88, 14, 17) # x
	Serpentine12.SetIconLocation(121, pTextureHandle, 147,  88, 14, 20) # y
	Serpentine12.SetIconLocation(122, pTextureHandle, 162,  88, 13, 17) # z
	Serpentine12.SetIconLocation(123, pTextureHandle, 176,  88,  9, 18) # {
	Serpentine12.SetIconLocation(124, pTextureHandle, 186,  88,  3, 17) # |
	Serpentine12.SetIconLocation(125, pTextureHandle, 190,  88,  9, 18) # }
	Serpentine12.SetIconLocation(126, pTextureHandle, 200,  88,  8, 11) # ~

#	Serpentine12.SetIconLocation(162, pTextureHandle, , , , ) # ¢
#	Serpentine12.SetIconLocation(163, pTextureHandle, , , , ) # £
#	Serpentine12.SetIconLocation(165, pTextureHandle, , , , ) # ¥
#	Serpentine12.SetIconLocation(170, pTextureHandle, , , , ) # ª
#	Serpentine12.SetIconLocation(186, pTextureHandle, , , , ) # º
#	Serpentine12.SetIconLocation(191, pTextureHandle, , , , ) # ¿
#	Serpentine12.SetIconLocation(196, pTextureHandle, , , , ) # Ä
#	Serpentine12.SetIconLocation(197, pTextureHandle, , , , ) # Å
#	Serpentine12.SetIconLocation(198, pTextureHandle, , , , ) # Æ
#	Serpentine12.SetIconLocation(199, pTextureHandle, , , , ) # Ç
#	Serpentine12.SetIconLocation(201, pTextureHandle, , , , ) # É
#	Serpentine12.SetIconLocation(209, pTextureHandle, , , , ) # Ñ
#	Serpentine12.SetIconLocation(212, pTextureHandle, , , , ) # Ô
#	Serpentine12.SetIconLocation(214, pTextureHandle, , , , ) # Ö
#	Serpentine12.SetIconLocation(220, pTextureHandle, , , , ) # Ü
#	Serpentine12.SetIconLocation(223, pTextureHandle, , , , ) # ß
#	Serpentine12.SetIconLocation(224, pTextureHandle, , , , ) # à
#	Serpentine12.SetIconLocation(225, pTextureHandle, , , , ) # á
#	Serpentine12.SetIconLocation(226, pTextureHandle, , , , ) # â
#	Serpentine12.SetIconLocation(228, pTextureHandle, , , , ) # ä
#	Serpentine12.SetIconLocation(229, pTextureHandle, , , , ) # å
#	Serpentine12.SetIconLocation(230, pTextureHandle, , , , ) # æ
#	Serpentine12.SetIconLocation(231, pTextureHandle, , , , ) # ç
#	Serpentine12.SetIconLocation(232, pTextureHandle, , , , ) # è
#	Serpentine12.SetIconLocation(233, pTextureHandle, , , , ) # é
#	Serpentine12.SetIconLocation(234, pTextureHandle, , , , ) # ê
#	Serpentine12.SetIconLocation(235, pTextureHandle, , , , ) # ë
#	Serpentine12.SetIconLocation(236, pTextureHandle, , , , ) # ì
#	Serpentine12.SetIconLocation(237, pTextureHandle, , , , ) # í
#	Serpentine12.SetIconLocation(238, pTextureHandle, , , , ) # î
#	Serpentine12.SetIconLocation(239, pTextureHandle, , , , ) # ï
#	Serpentine12.SetIconLocation(241, pTextureHandle, , , , ) # ñ
#	Serpentine12.SetIconLocation(242, pTextureHandle, , , , ) # ò
#	Serpentine12.SetIconLocation(243, pTextureHandle, , , , ) # ó
#	Serpentine12.SetIconLocation(245, pTextureHandle, , , , ) # ö
#	Serpentine12.SetIconLocation(248, pTextureHandle, , , , ) # ù
#	Serpentine12.SetIconLocation(249, pTextureHandle, , , , ) # ú
#	Serpentine12.SetIconLocation(250, pTextureHandle, , , , ) # û
#	Serpentine12.SetIconLocation(251, pTextureHandle, , , , ) # ü
#	Serpentine12.SetIconLocation(254, pTextureHandle, , , , ) # ÿ

##	Serpentine12.SetIconLocation(158, pTextureHandle, , , , ) # (Pt)
##	Serpentine12.SetIconLocation(159, pTextureHandle, , , , ) # (f with curved bottom)

