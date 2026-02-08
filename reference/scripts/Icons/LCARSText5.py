import App

# Function to load LCARSText5 font.
def LoadLCARSText5(LCARSText5 = None):
	if LCARSText5 is None:
		# Create font group.
		LCARSText5 = App.g_kFontManager.CreateFontGroup("LCARSText", 5.0)
		# Add LCARSText5 font group to FontManager
		App.g_kFontManager.AddFontGroup(LCARSText5)

	# Load font texture
	pTextureHandle = LCARSText5.LoadIconTexture('Data/Icons/LCARSText5.tga')

	# Set spacing
	LCARSText5.SetHorizontalSpacing(0.0)
	LCARSText5.SetVerticalSpacing(2.0)
	LCARSText5.SetSpaceWidth(4.0)
	LCARSText5.SetTabWidth(16.0)

	# Special characters
	LCARSText5.SetIconLocation(0,				pTextureHandle,  31, 31,  1,  1) # Box shape
	LCARSText5.SetIconLocation(App.WC_CURSOR,	pTextureHandle,  31, 31,  1,  1) # Cursor
	LCARSText5.SetIconLocation(App.WC_TAB,		pTextureHandle,  31, 31,  1, 1)	 # Tab
	LCARSText5.SetIconLocation(App.WC_SPACE,	pTextureHandle,  31, 31,  1, 1)	 # Space

	# Define icon locations
	LCARSText5.SetIconLocation( 48, pTextureHandle,  23,  11,  4, 10) # 0
	LCARSText5.SetIconLocation( 49, pTextureHandle,   0,   0,  3, 10) # 1
	LCARSText5.SetIconLocation( 50, pTextureHandle,   4,   0,  4, 10) # 2
	LCARSText5.SetIconLocation( 51, pTextureHandle,  10,   0,  4, 10) # 3
	LCARSText5.SetIconLocation( 52, pTextureHandle,  15,   0,  4, 10) # 4
	LCARSText5.SetIconLocation( 53, pTextureHandle,  21,   0,  4, 10) # 5
	LCARSText5.SetIconLocation( 54, pTextureHandle,   0,  11,  4, 10) # 6
	LCARSText5.SetIconLocation( 55, pTextureHandle,   6,  11,  4, 10) # 7
	LCARSText5.SetIconLocation( 56, pTextureHandle,  11,  11,  4, 10) # 8
	LCARSText5.SetIconLocation( 57, pTextureHandle,  17,  11,  4, 10) # 9
