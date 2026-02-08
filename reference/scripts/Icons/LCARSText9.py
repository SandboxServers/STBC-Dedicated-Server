import App

# Function to load LCARSText9 font.
def LoadLCARSText9(LCARSText9 = None):
	if LCARSText9 is None:
		# Create font group.
		LCARSText9 = App.g_kFontManager.CreateFontGroup("LCARSText", 9.0)
		# Add LCARSText9 font group to FontManager
		App.g_kFontManager.AddFontGroup(LCARSText9)

	# Load font texture
	pTextureHandle = LCARSText9.LoadIconTexture('Data/Icons/LCARSText9.tga')

	# Set spacing
	LCARSText9.SetHorizontalSpacing(0.0)
	LCARSText9.SetVerticalSpacing(2.0)
	LCARSText9.SetSpaceWidth(8.0)
	LCARSText9.SetTabWidth(32.0)

	# Special characters
	LCARSText9.SetIconLocation(  0,			pTextureHandle,  63, 31,  1,  1) # Box shape
	LCARSText9.SetIconLocation(App.WC_CURSOR,	pTextureHandle,  63, 31,  1,  1) # Cursor
	LCARSText9.SetIconLocation(App.WC_TAB,	pTextureHandle,  63, 31,  1,  1) # Tab
	LCARSText9.SetIconLocation(App.WC_SPACE,	pTextureHandle,  63, 31,  1,  1) # Space

	# Define icon locations
	LCARSText9.SetIconLocation( 48, pTextureHandle,  30,  16,  6, 16) # 0
	LCARSText9.SetIconLocation( 49, pTextureHandle,   0,   0,  4, 16) # 1
	LCARSText9.SetIconLocation( 50, pTextureHandle,   5,   0,  6, 16) # 2
	LCARSText9.SetIconLocation( 51, pTextureHandle,  12,   0,  7, 16) # 3
	LCARSText9.SetIconLocation( 52, pTextureHandle,  20,   0,  8, 16) # 4
	LCARSText9.SetIconLocation( 53, pTextureHandle,  29,   0,  7, 16) # 5
	LCARSText9.SetIconLocation( 54, pTextureHandle,   0,  16,  6, 16) # 6
	LCARSText9.SetIconLocation( 55, pTextureHandle,   7,  16,  7, 16) # 7
	LCARSText9.SetIconLocation( 56, pTextureHandle,  15,  16,  6, 16) # 8
	LCARSText9.SetIconLocation( 57, pTextureHandle,  22,  16,  7, 16) # 9
