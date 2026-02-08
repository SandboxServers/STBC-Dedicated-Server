import App

# Function to load Frame icon group
def LoadFrame(Frame = None):
	
	# Setup
	if Frame is None:
		Frame = App.g_kIconManager.CreateIconGroup("Frame")
		# Add Frame icon group to IconManager
		App.g_kIconManager.AddIconGroup(Frame)
	
	TextureHandle = Frame.LoadIconTexture('Data/Icons/Frame.tga')

	# Define icon locations

	# Frame and solid center have the following layout
	#			0	1	2
	#
	#			3	4	5
	#
	#			6	7	8
	Frame.SetIconLocation(0, TextureHandle,  0,  0,  20, 20)
	Frame.SetIconLocation(1, TextureHandle, 22,  0,  9, 20)
	Frame.SetIconLocation(2, TextureHandle, 33,  0,  20, 20)
	Frame.SetIconLocation(3, TextureHandle,  0, 22,  20, 9)
	Frame.SetIconLocation(4, TextureHandle, 22, 22,  9, 9)
	Frame.SetIconLocation(5, TextureHandle, 33, 22,  20, 9)
	Frame.SetIconLocation(6, TextureHandle,  0, 33,  20, 20)
	Frame.SetIconLocation(7, TextureHandle, 22, 33,  9, 20)
	Frame.SetIconLocation(8, TextureHandle, 32, 32,  21, 21)
