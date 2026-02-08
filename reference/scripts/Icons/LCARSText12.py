import App

# Function to load LCARSText12 font.
def LoadLCARSText12(LCARSText12 = None):
	if LCARSText12 is None:
		# Create font group.
		LCARSText12 = App.g_kFontManager.CreateFontGroup("LCARSText", 12.0)
		# Add LCARSText12 font group to FontManager
		App.g_kFontManager.AddFontGroup(LCARSText12)

	# Load font texture
	pTextureHandle = LCARSText12.LoadIconTexture('Data/Icons/LCARSText12.tga')

	# Set spacing
	LCARSText12.SetHorizontalSpacing(0.0)
	LCARSText12.SetVerticalSpacing(4.0)
	LCARSText12.SetSpaceWidth(8.0)
	LCARSText12.SetTabWidth(32.0)

	# Special characters
	LCARSText12.SetIconLocation(0,			pTextureHandle,  63,  63,  1,  1) # Box shape
	LCARSText12.SetIconLocation(App.WC_CURSOR,pTextureHandle,  63,  63,  1,  1) # Cursor
	LCARSText12.SetIconLocation(App.WC_TAB,	pTextureHandle,  63,  63,  1,  1) # Tab
	LCARSText12.SetIconLocation(App.WC_SPACE,	pTextureHandle,  63,  63,  1,  1) # Space

	# Define icon locations
	LCARSText12.SetIconLocation( 48, pTextureHandle,  38,  21,  8, 21) # 0
	LCARSText12.SetIconLocation( 49, pTextureHandle,   0,   0,  5, 21) # 1
	LCARSText12.SetIconLocation( 50, pTextureHandle,   6,   0,  8, 21) # 2
	LCARSText12.SetIconLocation( 51, pTextureHandle,  15,   0,  9, 21) # 3
	LCARSText12.SetIconLocation( 52, pTextureHandle,  25,   0, 10, 21) # 4
	LCARSText12.SetIconLocation( 53, pTextureHandle,  36,   0,  9, 21) # 5
	LCARSText12.SetIconLocation( 54, pTextureHandle,   0,  21,  8, 21) # 6
	LCARSText12.SetIconLocation( 55, pTextureHandle,   9,  21,  9, 21) # 7
	LCARSText12.SetIconLocation( 56, pTextureHandle,  19,  21,  8, 21) # 8
	LCARSText12.SetIconLocation( 57, pTextureHandle,  28,  21,  9, 21) # 9
