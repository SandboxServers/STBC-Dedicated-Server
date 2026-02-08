import App

# Function to load Arial font.
def LoadArial(Arial = None):
	
	if Arial is None:
		# Create font group.
		Arial = App.g_kFontManager.CreateFontGroup("Arial", 8.0)
		# Add Arial font group to IconManager
		App.g_kFontManager.AddFontGroup(Arial)

	# Load font texture
	pTextureHandle = Arial.LoadIconTexture('Data/Icons/arial.tga')

	# Set spacing
	Arial.SetHorizontalSpacing(2.0)
	Arial.SetVerticalSpacing(2.0)
	Arial.SetSpaceWidth(6.0)
	Arial.SetTabWidth(24.0)

	# Special characters
	Arial.SetIconLocation(  0,			pTextureHandle, 122, 50,  5, 9) # Box shape
	Arial.SetIconLocation(App.WC_CURSOR,pTextureHandle,  50, 51, 1, 13) # Cursor
	Arial.SetIconLocation(App.WC_SPACE, pTextureHandle, 122, 51, 5, 13) # Space
	Arial.SetIconLocation(App.WC_TAB,	pTextureHandle, 122, 51, 1, 13) # Tab

	# Define icon locations
	Arial.SetIconLocation( 33, pTextureHandle,  76, 39,  1, 11) # !
	Arial.SetIconLocation( 34, pTextureHandle,  83, 51,  3, 13) # "
	Arial.SetIconLocation( 35, pTextureHandle,  91, 39,  8, 11) # #
	Arial.SetIconLocation( 36, pTextureHandle, 100, 39,  4, 11) # $
	Arial.SetIconLocation( 37, pTextureHandle, 107, 39, 10, 11) # %
	Arial.SetIconLocation( 38, pTextureHandle, 104, 39, 11, 11) # &
	Arial.SetIconLocation( 39, pTextureHandle,  81, 51,  1, 13) # '
	Arial.SetIconLocation( 40, pTextureHandle,  15, 51,  3, 13) # (
	Arial.SetIconLocation( 41, pTextureHandle,  18, 51,  3, 13) # )
	Arial.SetIconLocation( 42, pTextureHandle,   9, 51,  5, 13) # *
	Arial.SetIconLocation( 43, pTextureHandle,  42, 51,  7, 13) # +
	Arial.SetIconLocation( 44, pTextureHandle,  89, 51,  1, 13) # ,
	Arial.SetIconLocation( 45, pTextureHandle,  22, 51,  3, 13) # -
	Arial.SetIconLocation( 46, pTextureHandle,  92, 51,  1, 13) # .
	Arial.SetIconLocation( 47, pTextureHandle, 111, 51,  3, 13) # /
	Arial.SetIconLocation( 48, pTextureHandle,  35, 14,  6, 13) # 0
	Arial.SetIconLocation( 49, pTextureHandle,  42, 14,  3, 13) # 1
	Arial.SetIconLocation( 50, pTextureHandle,  46, 14,  6, 13) # 2
	Arial.SetIconLocation( 51, pTextureHandle,  53, 14,  6, 13) # 3
	Arial.SetIconLocation( 52, pTextureHandle,  60, 14,  6, 13) # 4
	Arial.SetIconLocation( 53, pTextureHandle,  67, 14,  6, 13) # 5
	Arial.SetIconLocation( 54, pTextureHandle,  74, 14,  6, 13) # 6
	Arial.SetIconLocation( 55, pTextureHandle,  81, 14,  6, 13) # 7
	Arial.SetIconLocation( 56, pTextureHandle,  88, 14,  5, 13) # 8
	Arial.SetIconLocation( 57, pTextureHandle,  95, 14,  6, 13) # 9
	Arial.SetIconLocation( 58, pTextureHandle,  77, 51,  1, 13) # :
	Arial.SetIconLocation( 59, pTextureHandle,  73, 51,  1, 13) # ;
	Arial.SetIconLocation( 60, pTextureHandle,  96, 51,  6, 13) # <
	Arial.SetIconLocation( 61, pTextureHandle,  33, 51,  7, 13) # =
	Arial.SetIconLocation( 62, pTextureHandle, 104, 51,  6, 13) # >
	Arial.SetIconLocation( 63, pTextureHandle, 116, 51,  5, 13) # ?
	Arial.SetIconLocation( 64, pTextureHandle,  78, 39, 12, 11) # @
	Arial.SetIconLocation( 65, pTextureHandle, 102, 14,  9, 10) # A
	Arial.SetIconLocation( 66, pTextureHandle, 112, 14,  7, 10) # B
	Arial.SetIconLocation( 67, pTextureHandle, 120, 14,  7, 10) # C
	Arial.SetIconLocation( 68, pTextureHandle,   0, 28,  7, 11) # D
	Arial.SetIconLocation( 69, pTextureHandle,   8, 28,  7, 11) # E
	Arial.SetIconLocation( 70, pTextureHandle,  16, 28,  6, 10) # F
	Arial.SetIconLocation( 71, pTextureHandle,  23, 28,  8, 10) # G
	Arial.SetIconLocation( 72, pTextureHandle,  32, 28,  7, 10) # H
	Arial.SetIconLocation( 73, pTextureHandle,  40, 28,  1, 10) # I
	Arial.SetIconLocation( 74, pTextureHandle,  42, 28,  5, 10) # J
	Arial.SetIconLocation( 75, pTextureHandle,  48, 28,  8, 10) # K
	Arial.SetIconLocation( 76, pTextureHandle,  57, 28,  6, 10) # L
	Arial.SetIconLocation( 77, pTextureHandle,  64, 28,  9, 10) # M
	Arial.SetIconLocation( 78, pTextureHandle,  74, 28,  7, 10) # N
	Arial.SetIconLocation( 79, pTextureHandle,  82, 28,  8, 10) # O
	Arial.SetIconLocation( 80, pTextureHandle,  91, 28,  7, 10) # P
	Arial.SetIconLocation( 81, pTextureHandle,  99, 28,  8, 10) # Q
	Arial.SetIconLocation( 82, pTextureHandle, 108, 28,  7, 10) # R
	Arial.SetIconLocation( 83, pTextureHandle, 116, 28,  7, 10) # S
	Arial.SetIconLocation( 84, pTextureHandle,   0, 39,  7, 10) # T
	Arial.SetIconLocation( 85, pTextureHandle,   8, 39,  7, 10) # U
	Arial.SetIconLocation( 86, pTextureHandle,  16, 39,  9, 10) # V
	Arial.SetIconLocation( 87, pTextureHandle,  26, 39, 13, 10) # W
	Arial.SetIconLocation( 88, pTextureHandle,  40, 39,  7, 10) # X
	Arial.SetIconLocation( 89, pTextureHandle,  48, 39,  7, 10) # Y
	Arial.SetIconLocation( 90, pTextureHandle,  56, 39,  7, 10) # Z
	Arial.SetIconLocation( 91, pTextureHandle,  50, 51,  2, 13) # [
	Arial.SetIconLocation( 92, pTextureHandle,  65, 51,  4, 13) # \
	Arial.SetIconLocation( 93, pTextureHandle,  54, 51,  2, 13) # ]
	Arial.SetIconLocation( 94, pTextureHandle, 118, 39,  5, 11) # ^
	Arial.SetIconLocation( 95, pTextureHandle,  26, 51,  7, 13) # _
	Arial.SetIconLocation( 96, pTextureHandle,  65, 39,  1, 11) # `
	Arial.SetIconLocation( 97, pTextureHandle,   0,  0,  5, 13) # a
	Arial.SetIconLocation( 98, pTextureHandle,   7,  0,  5, 13) # b
	Arial.SetIconLocation( 99, pTextureHandle,  14,  0,  5, 13) # c
	Arial.SetIconLocation(100, pTextureHandle,  21,  0,  5, 13) # d
	Arial.SetIconLocation(101, pTextureHandle,  28,  0,  5, 13) # e
	Arial.SetIconLocation(102, pTextureHandle,  34,  0,  4, 13) # f
	Arial.SetIconLocation(103, pTextureHandle,  38,  0,  5, 13) # g
	Arial.SetIconLocation(104, pTextureHandle,  45,  0,  5, 13) # h
	Arial.SetIconLocation(105, pTextureHandle,  52,  0,  1, 13) # i
	Arial.SetIconLocation(106, pTextureHandle,  53,  0,  3, 13) # j
	Arial.SetIconLocation(107, pTextureHandle,  58,  0,  5, 13) # k
	Arial.SetIconLocation(108, pTextureHandle,  65,  0,  1, 13) # l
	Arial.SetIconLocation(109, pTextureHandle,  68,  0,  9, 13) # m
	Arial.SetIconLocation(110, pTextureHandle,  79,  0,  5, 13) # n
	Arial.SetIconLocation(111, pTextureHandle,  86,  0,  5, 13) # o
	Arial.SetIconLocation(112, pTextureHandle,  92,  0,  6, 13) # p
	Arial.SetIconLocation(113, pTextureHandle, 100,  0,  5, 13) # q
	Arial.SetIconLocation(114, pTextureHandle, 106,  0,  4, 13) # r
	Arial.SetIconLocation(115, pTextureHandle, 111,  0,  5, 13) # s
	Arial.SetIconLocation(116, pTextureHandle, 117,  0,  3, 13) # t
	Arial.SetIconLocation(117, pTextureHandle, 122,  0,  5, 13) # u
	Arial.SetIconLocation(118, pTextureHandle,   0, 14,  5, 13) # v
	Arial.SetIconLocation(119, pTextureHandle,   6, 14,  9, 13) # w
	Arial.SetIconLocation(120, pTextureHandle,  16, 14,  5, 13) # x
	Arial.SetIconLocation(121, pTextureHandle,  23, 14,  5, 13) # y
	Arial.SetIconLocation(122, pTextureHandle,  29, 14,  5, 13) # z
	Arial.SetIconLocation(123, pTextureHandle,  57, 51,  3, 13) # {
	Arial.SetIconLocation(124, pTextureHandle,  70, 51,  1, 12) # |
	Arial.SetIconLocation(125, pTextureHandle,  62, 51,  3, 13) # }
	Arial.SetIconLocation(126, pTextureHandle,  67, 39,  7, 11) # ~
