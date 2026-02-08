import App

# Load the System Icons icon group.
def LoadSystemIcons(kIcons = None):
	
	# Setup
	if kIcons is None:
		kIcons = App.g_kIconManager.CreateIconGroup("System")
		# Add group to manager.
		App.g_kIconManager.AddIconGroup(kIcons)
	
	# Mouse cursor
	kTextureHandle = kIcons.LoadIconTexture('Data/Icons/TrekCursor.tga')
	kIcons.SetIconLocation(0, kTextureHandle, 34,  0, 16, 20)
	kIcons.SetIconLocation(1, kTextureHandle,  0, 34, 20, 24)
	kIcons.SetIconLocation(2, kTextureHandle,  0,  0, 26, 32)
	kIcons.SetIconLocation(3, kTextureHandle, 32, 24, 32, 40)

	# Target cursor
	kTextureHandle = kIcons.LoadIconTexture("Data/Icons/TargetCursors1.tga")
	kIcons.SetIconLocation(10, kTextureHandle, 41,  0, 20, 20)
	kIcons.SetIconLocation(11, kTextureHandle, 39, 20, 24, 24)
	kIcons.SetIconLocation(12, kTextureHandle,  0,  0, 32, 32)

	# Circle cursor
	kIcons.SetIconLocation(20, kTextureHandle, 41, 44, 20, 20)
	kIcons.SetIconLocation(22, kTextureHandle,  0, 32, 32, 32)
	kTextureHandle = kIcons.LoadIconTexture("Data/Icons/TargetCursors2.tga")
	kIcons.SetIconLocation(21, kTextureHandle, 0, 0, 24, 24)
	
	# Slider for numeric bar controls.
	kTextureHandle = kIcons.LoadIconTexture("Data/Icons/BarSlider.tga")
	kIcons.SetIconLocation(100, kTextureHandle, 0, 0, 10, 18)

	# Noise icons (static)
	kTextureHandle = kIcons.LoadIconTexture("Data/Textures/Effects/Noise1.tga")
	kIcons.SetIconLocation(200, kTextureHandle, 0, 0, 200, 200)
	kTextureHandle = kIcons.LoadIconTexture("Data/Textures/Effects/Noise2.tga")
	kIcons.SetIconLocation(201, kTextureHandle, 0, 0, 200, 200)
	kTextureHandle = kIcons.LoadIconTexture("Data/Textures/Effects/Noise3.tga")
	kIcons.SetIconLocation(202, kTextureHandle, 0, 0, 200, 200)

#
# GetScreenResWidth()
#
def GetScreenResWidth():
	if (App.g_kIconManager.GetScreenWidth() == 800):
		return 1
	elif (App.g_kIconManager.GetScreenWidth() == 1024):
		return 2
	elif (App.g_kIconManager.GetScreenWidth() == 1280):
		return 3
	elif (App.g_kIconManager.GetScreenWidth() == 1600):
		return 4
	return 0	# 640 or any other res (other than 640 is bad...)

#
# SetTrekCursor()
#
def SetTrekCursor():
	iCentering = App.TGRootPane.MCPP_HORIZONTAL_CENTER + App.TGRootPane.MCPP_VERTICAL_TOP
	iResWidth = GetScreenResWidth()
	fScale = 1.0
	if (iResWidth == 4):
		iResWidth = 2		# Make 1600x1200 a 1.5 scale of 1024x768
		fScale = 1.5
	App.g_kRootWindow.SetMouseCursor("System", 0 + iResWidth, iCentering, fScale)

def PushTrekCursor():							
	iCentering = App.TGRootPane.MCPP_HORIZONTAL_CENTER + App.TGRootPane.MCPP_VERTICAL_TOP
	iResWidth = GetScreenResWidth()
	fScale = 1.0
	if (iResWidth == 4):
		iResWidth = 2		# Make 1600x1200 a 1.5 scale of 1024x768
		fScale = 1.5
	App.g_kRootWindow.PushCursor("System", 0 + iResWidth, iCentering, fScale)

#
# SetTargetCursor()
#
g_kTargetCursorScales = [1.0, 1.0, 1.0, 1.25, 1.5]
def SetTargetCursor():
	iCentering = App.TGRootPane.MCPP_HORIZONTAL_CENTER + App.TGRootPane.MCPP_VERTICAL_CENTER
	iResWidth = GetScreenResWidth()
	fScale = g_kTargetCursorScales[iResWidth]
	if (iResWidth > 2):
		iResWidth = 2		# Cap at 1024, we scale from here
	App.g_kRootWindow.SetMouseCursor("System", 10 + iResWidth, iCentering, fScale)

#
# SetCircleCursor()
#
g_kCircleCursorScales = [1.0, 1.0, 1.0, 1.25, 1.5]
def SetCircleCursor():
	iCentering = App.TGRootPane.MCPP_HORIZONTAL_CENTER + App.TGRootPane.MCPP_VERTICAL_CENTER
	iResWidth = GetScreenResWidth()
	fScale = g_kCircleCursorScales[iResWidth]
	if (iResWidth > 2):
		iResWidth = 2		# Cap at 1024, we scale from here
	App.g_kRootWindow.SetMouseCursor("System", 20 + iResWidth, iCentering, fScale)
