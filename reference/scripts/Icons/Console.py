import App

# Function to load Console icon group
def LoadConsole(Console = None):
	
	if Console is None:
		# Setup
		Console = App.g_kIconManager.CreateIconGroup("Console")
		# Add Colors icon group to IconManager
		App.g_kIconManager.AddIconGroup(Console)
	
	TextureHandle = Console.LoadIconTexture('Data/Icons/Console.tga')

	# Define icon locations
	Console.SetIconLocation(0, TextureHandle,  0,  0,  256, 128)
