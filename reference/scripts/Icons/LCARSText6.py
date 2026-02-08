import App

# Function to load LCARSText6 font.
def LoadLCARSText6(LCARSText6 = None):
	if LCARSText6 is None:
		# Create font group.
		LCARSText6 = App.g_kFontManager.CreateFontGroup("LCARSText", 6.0)
		# Add LCARSText6 font group to FontManager
		App.g_kFontManager.AddFontGroup(LCARSText6)

	# Load font texture
	pTextureHandle = LCARSText6.LoadIconTexture('Data/Icons/LCARSText6.tga')

	# Set spacing
	LCARSText6.SetHorizontalSpacing(1.0)
	LCARSText6.SetVerticalSpacing(2.0)
	LCARSText6.SetSpaceWidth(5.0)
	LCARSText6.SetTabWidth(20.0)

	# Special characters
	LCARSText6.SetIconLocation(0,				pTextureHandle,  31, 31,  1,  1) # Box shape
	LCARSText6.SetIconLocation(App.WC_CURSOR,	pTextureHandle,  31, 31,  1,  1) # Cursor
	LCARSText6.SetIconLocation(App.WC_TAB,	pTextureHandle,  31, 31,  1,  1) # Tab
	LCARSText6.SetIconLocation(App.WC_SPACE,	pTextureHandle,  31, 31,  1,  1) # Space

	# Define icon locations
	LCARSText6.SetIconLocation( 48, pTextureHandle,  22,  12,  4, 12) # 0
	LCARSText6.SetIconLocation( 49, pTextureHandle,   0,   0,  4, 12) # 1
	LCARSText6.SetIconLocation( 50, pTextureHandle,   5,   0,  4, 12) # 2
	LCARSText6.SetIconLocation( 51, pTextureHandle,  10,   0,  5, 12) # 3
	LCARSText6.SetIconLocation( 52, pTextureHandle,  16,   0,  6, 12) # 4
	LCARSText6.SetIconLocation( 53, pTextureHandle,  23,   0,  5, 12) # 5
	LCARSText6.SetIconLocation( 54, pTextureHandle,   0,  12,  4, 12) # 6
	LCARSText6.SetIconLocation( 55, pTextureHandle,   5,  12,  5, 12) # 7
	LCARSText6.SetIconLocation( 56, pTextureHandle,  11,  12,  4, 12) # 8
	LCARSText6.SetIconLocation( 57, pTextureHandle,  16,  12,  5, 12) # 9
