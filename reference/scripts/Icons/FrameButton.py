import App

# Function to load Button icon group
def LoadFrameButton(Button = None):
	
	# Setup
	if Button is None:
		Button = App.g_kIconManager.CreateIconGroup("FrameButton")
		# Add Button icon group to IconManager
		App.g_kIconManager.AddIconGroup(Button)
	
	TextureHandle = Button.LoadIconTexture('Data/Icons/Frame.tga')

	# Define icon locations

	# Button and solid center have the following layout
	#			0	1	2
	#
	#			3	4	5
	#
	#			6	7	8
	Button.SetIconLocation(0, TextureHandle,  0,  0,  20, 20)
	Button.SetIconLocation(1, TextureHandle, 22,  0,  9, 20)
	Button.SetIconLocation(2, TextureHandle, 33,  0,  20, 20)
	Button.SetIconLocation(3, TextureHandle,  0, 22,  20, 9)
	Button.SetIconLocation(4, TextureHandle, 22, 22,  9, 9)
	Button.SetIconLocation(5, TextureHandle, 33, 22,  20, 9)
	Button.SetIconLocation(6, TextureHandle,  0, 33,  20, 20)
	Button.SetIconLocation(7, TextureHandle, 22, 33,  9, 20)
	Button.SetIconLocation(8, TextureHandle, 32, 32,  21, 21)

	TextureHandle = Button.LoadIconTexture('Data/Icons/Button.tga')
	Button.SetIconLocation(9, TextureHandle,  0,  0,  13, 9)
	Button.SetIconLocation(10, TextureHandle, 14,  0,  99, 9)
	Button.SetIconLocation(11, TextureHandle, 114,  0,  14, 9)
	Button.SetIconLocation(12, TextureHandle,  0, 10,  13, 44)
	Button.SetIconLocation(13, TextureHandle, 14, 10,  99, 44)
	Button.SetIconLocation(14, TextureHandle, 114, 10,  14, 44)
	Button.SetIconLocation(15, TextureHandle,  0, 55,  13, 4)
	Button.SetIconLocation(16, TextureHandle, 14, 55,  99, 4)
	Button.SetIconLocation(17, TextureHandle, 114, 55, 14, 4)

	Button.SetIconLocation(18, TextureHandle,  0,  0,  13, 9)
	Button.SetIconLocation(19, TextureHandle, 14,  0,  99, 9)
	Button.SetIconLocation(20, TextureHandle, 114,  0,  14, 9)
	Button.SetIconLocation(21, TextureHandle,  0, 10,  13, 44)
	Button.SetIconLocation(22, TextureHandle, 14, 10,  99, 44)
	Button.SetIconLocation(23, TextureHandle, 114, 10,  14, 44)
	Button.SetIconLocation(24, TextureHandle,  0, 55,  13, 4)
	Button.SetIconLocation(25, TextureHandle, 14, 55,  99, 4)
	Button.SetIconLocation(26, TextureHandle, 114, 55, 14, 4)
