import App

# Load the EffectTextures icon group.
def LoadReticleTextures(Icons = None):
	
	# Setup
	if(Icons is None):
		Icons = App.g_kIconManager.CreateIconGroup("ReticleTextures")
		# Add group to manager.
		App.g_kIconManager.AddIconGroup(Icons)

	kTexture = Icons.LoadIconTexture("data/target.tga")
	# Upper left
	Icons.SetIconLocation(0, kTexture, 0, 0, 16, 8)
	# Upper right
	Icons.SetIconLocation(1, kTexture, 0, 0, 16, 8, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_HORIZONTAL)
	# Lower left
	Icons.SetIconLocation(2, kTexture, 0, 0, 16, 8, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_VERTICAL)
	# Lower right
	Icons.SetIconLocation(3, kTexture, 0, 0, 16, 8, App.TGIconGroup.ROTATE_180, App.TGIconGroup.MIRROR_NONE)
 
 	# Subcomponent
	kTexture = Icons.LoadIconTexture("data/subtarget.tga")
	Icons.SetIconLocation(4, kTexture, 0, 0, 8, 8)

	# half of arrows
	kTexture = Icons.LoadIconTexture("data/corner.tga")
	# Upper left
	Icons.SetIconLocation(5, kTexture, 0, 0, 16, 16)
	# Upper right
	Icons.SetIconLocation(6, kTexture, 0, 0, 16, 16, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_HORIZONTAL)
	# Lower left
	Icons.SetIconLocation(7, kTexture, 0, 0, 16, 16, App.TGIconGroup.ROTATE_0, App.TGIconGroup.MIRROR_VERTICAL)
	# Lower right
	Icons.SetIconLocation(8, kTexture, 0, 0, 16, 16, App.TGIconGroup.ROTATE_180, App.TGIconGroup.MIRROR_NONE)

