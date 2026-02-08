import App

# Function to load pGroup icon group
def LoadTargetArrows(pGroup = None):
	
	# Setup
	if pGroup is None:
		pGroup = App.g_kIconManager.CreateIconGroup("TargetArrow")
		# Add pGroup icon group to IconManager
		App.g_kIconManager.AddIconGroup(pGroup)
	
	TextureHandle = pGroup.LoadIconTexture('Data/Icons/TargetArrow.tga')

	# Define icon locations

	# pGroup and solid center have the following layout
	#			0	1	2
	#
	#			3		4
	#
	#			5	6	7
	pGroup.SetIconLocation(0, TextureHandle,  0,  0,  22, 22)
	pGroup.SetIconLocation(1, TextureHandle, 24,  0,  17, 23)
	pGroup.SetIconLocation(2, TextureHandle,  0,  0,  22, 22, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_HORIZONTAL)
	pGroup.SetIconLocation(3, TextureHandle, 41,  0,  23, 17)
	pGroup.SetIconLocation(4, TextureHandle, 41,  0,  23, 17, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_HORIZONTAL)
	pGroup.SetIconLocation(5, TextureHandle,  0,  0,  22, 22, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_VERTICAL)
	pGroup.SetIconLocation(6, TextureHandle, 24,  0,  17, 23, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_VERTICAL)
	pGroup.SetIconLocation(7, TextureHandle,  0,  0,  22, 22, App.TGIconGroup.ROTATE_180, App.TGIconGroup.MIRROR_NONE)

#	pGroup.SetIconLocation(0, TextureHandle,  0,  0,  22, 22)
#	pGroup.SetIconLocation(1, TextureHandle, 24,  0,  18, 23)
#	pGroup.SetIconLocation(2, TextureHandle, 43,  0,  22, 22)
#	pGroup.SetIconLocation(3, TextureHandle,  1, 23,  23, 17)
#	pGroup.SetIconLocation(4, TextureHandle, 41, 23,  23, 17)
#	pGroup.SetIconLocation(5, TextureHandle,  0, 42,  21, 22)
#	pGroup.SetIconLocation(6, TextureHandle, 24, 41,  18, 23)
#	pGroup.SetIconLocation(7, TextureHandle, 43, 42,  21, 22)

