import App

# Function to load LCARSText15 font.
def LoadLCARSText15(LCARSText15 = None):
	if LCARSText15 is None:
		# Create font group.
		LCARSText15 = App.g_kFontManager.CreateFontGroup("LCARSText", 15.0)
		# Add LCARSText15 font group to FontManager
		App.g_kFontManager.AddFontGroup(LCARSText15)

	# Load font texture
	pTextureHandle = LCARSText15.LoadIconTexture('Data/Icons/LCARSText15.tga')

	# Set spacing
	LCARSText15.SetHorizontalSpacing(2.0)
	LCARSText15.SetVerticalSpacing(5.0)
	LCARSText15.SetSpaceWidth(10.0)
	LCARSText15.SetTabWidth(40.0)

	# Special characters
	LCARSText15.SetIconLocation(0,			pTextureHandle,  63,  63,  1,  1) # Box shape
	LCARSText15.SetIconLocation(App.WC_CURSOR,pTextureHandle,  63,  63,  1,  1) # Cursor
	LCARSText15.SetIconLocation(App.WC_TAB,	pTextureHandle,  63,  63,  1,  1) # Tab
	LCARSText15.SetIconLocation(App.WC_SPACE,	pTextureHandle,  63,  63,  1,  1) # Space

	# Define icon locations
	LCARSText15.SetIconLocation( 48, pTextureHandle,  45,  25,  9, 25) # 0
	LCARSText15.SetIconLocation( 49, pTextureHandle,   0,   0,  7, 25) # 1
	LCARSText15.SetIconLocation( 50, pTextureHandle,   8,   0, 10, 25) # 2
	LCARSText15.SetIconLocation( 51, pTextureHandle,  19,   0, 10, 25) # 3
	LCARSText15.SetIconLocation( 52, pTextureHandle,  30,   0, 12, 25) # 4
	LCARSText15.SetIconLocation( 53, pTextureHandle,  43,   0, 10, 25) # 5
	LCARSText15.SetIconLocation( 54, pTextureHandle,   0,  25, 10, 25) # 6
	LCARSText15.SetIconLocation( 55, pTextureHandle,  11,  25, 11, 25) # 7
	LCARSText15.SetIconLocation( 56, pTextureHandle,  23,  25, 10, 25) # 8
	LCARSText15.SetIconLocation( 57, pTextureHandle,  34,  25, 10, 25) # 9
