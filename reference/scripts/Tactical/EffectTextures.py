import App

# Load the EffectTextures icon group.
def LoadEffectTextures(Icons = None):
	
	# Setup
	if(Icons is None):
		Icons = App.g_kIconManager.CreateIconGroup("EffectTextures")
		# Add group to manager.
		App.g_kIconManager.AddIconGroup(Icons)

	kTexture = Icons.LoadIconTexture('data/Textures/starstreak.tga')
	Icons.SetIconLocation(0, kTexture, 0, 0, 64, 64)

	kTexture = Icons.LoadIconTexture('data/Textures/spacedust.tga')
	Icons.SetIconLocation(10, kTexture, 0, 0, 16, 16)

	pContainer = App.g_kTextureAnimManager.AddContainer("data/Textures/Effects/ExplosionA.tga")

	fTop = 0.0
	fMiddle = fTop + 0.125
	for i in range(8):
		pTrack = pContainer.AddTextureTrack(16)
		pTrack.SetFrame(0, 0.000000, 1.0 - fTop , 0.125000, 1.0 - fMiddle )
		pTrack.SetFrame(1, 0.125000, 1.0 - fTop , 0.250000, 1.0 - fMiddle )
		pTrack.SetFrame(2, 0.250000, 1.0 - fTop , 0.375000, 1.0 - fMiddle )
		pTrack.SetFrame(3, 0.375000, 1.0 - fTop , 0.500000, 1.0 - fMiddle )
		pTrack.SetFrame(4, 0.500000, 1.0 - fTop , 0.625000, 1.0 - fMiddle )
		pTrack.SetFrame(5, 0.625000, 1.0 - fTop , 0.750000, 1.0 - fMiddle )
		pTrack.SetFrame(6, 0.750000, 1.0 - fTop , 0.875000, 1.0 - fMiddle )
		pTrack.SetFrame(7, 0.875000, 1.0 - fTop , 1.000000, 1.0 - fMiddle )
		pTrack.SetFrame(8, 0.875000, 1.0 - fTop , 1.000000, 1.0 - fMiddle )
		pTrack.SetFrame(9, 0.875000, 1.0 - fTop , 1.000000, 1.0 - fMiddle )
		pTrack.SetFrame(10, 0.875000, 1.0 - fTop , 1.000000, 1.0 - fMiddle )
		pTrack.SetFrame(11, 0.875000, 1.0 - fTop , 1.000000, 1.0 - fMiddle )
		pTrack.SetFrame(12, 0.875000, 1.0 - fTop , 1.000000, 1.0 - fMiddle )
		pTrack.SetFrame(13, 0.875000, 1.0 - fTop , 1.000000, 1.0 - fMiddle )
		pTrack.SetFrame(14, 0.875000, 1.0 - fTop , 1.000000, 1.0 - fMiddle )
		pTrack.SetFrame(15, 0.875000, 1.0 - fTop , 1.000000, 1.0 - fMiddle )

		fTop = fTop + 0.125
		fMiddle = fTop + 0.125

	pContainer = App.g_kTextureAnimManager.AddContainer("data/Textures/Effects/ExplosionB.tga")

	fTop = 0.0
	fMiddle = fTop + 0.125
	for i in range(8):
		pTrack = pContainer.AddTextureTrack(16)
		pTrack.SetFrame(0, 0.000000, 1.0 - fTop , 0.125000, 1.0 - fMiddle )
		pTrack.SetFrame(1, 0.125000, 1.0 - fTop , 0.250000, 1.0 - fMiddle )
		pTrack.SetFrame(2, 0.250000, 1.0 - fTop , 0.375000, 1.0 - fMiddle )
		pTrack.SetFrame(3, 0.375000, 1.0 - fTop , 0.500000, 1.0 - fMiddle )
		pTrack.SetFrame(4, 0.500000, 1.0 - fTop , 0.625000, 1.0 - fMiddle )
		pTrack.SetFrame(5, 0.625000, 1.0 - fTop , 0.750000, 1.0 - fMiddle )
		pTrack.SetFrame(6, 0.750000, 1.0 - fTop , 0.875000, 1.0 - fMiddle )
		pTrack.SetFrame(7, 0.875000, 1.0 - fTop , 1.000000, 1.0 - fMiddle )
		pTrack.SetFrame(8, 0.875000, 1.0 - fTop , 1.000000, 1.0 - fMiddle )
		pTrack.SetFrame(9, 0.875000, 1.0 - fTop , 1.000000, 1.0 - fMiddle )
		pTrack.SetFrame(10, 0.875000, 1.0 - fTop , 1.000000, 1.0 - fMiddle )
		pTrack.SetFrame(11, 0.875000, 1.0 - fTop , 1.000000, 1.0 - fMiddle )
		pTrack.SetFrame(12, 0.875000, 1.0 - fTop , 1.000000, 1.0 - fMiddle )
		pTrack.SetFrame(13, 0.875000, 1.0 - fTop , 1.000000, 1.0 - fMiddle )
		pTrack.SetFrame(14, 0.875000, 1.0 - fTop , 1.000000, 1.0 - fMiddle )
		pTrack.SetFrame(15, 0.875000, 1.0 - fTop , 1.000000, 1.0 - fMiddle )

		fTop = fTop + 0.125
		fMiddle = fTop + 0.125

	pContainer = App.g_kTextureAnimManager.AddContainer("data/Textures/Effects/SunFlaresOrange.tga")
	fTop	= 0.125 / 2.0
	fMiddle	= 0.0

	for i in range(8):

		pTrack = pContainer.AddTextureTrack(8)

		pTrack.SetFrame(0, 0.000000, 1.0 - fTop , 0.125000, 1.0 - fMiddle )
		pTrack.SetFrame(1, 0.125000, 1.0 - fTop , 0.250000, 1.0 - fMiddle )
		pTrack.SetFrame(2, 0.250000, 1.0 - fTop , 0.375000, 1.0 - fMiddle )
		pTrack.SetFrame(3, 0.375000, 1.0 - fTop , 0.500000, 1.0 - fMiddle )
		pTrack.SetFrame(4, 0.500000, 1.0 - fTop , 0.625000, 1.0 - fMiddle )
		pTrack.SetFrame(5, 0.625000, 1.0 - fTop , 0.750000, 1.0 - fMiddle )
		pTrack.SetFrame(6, 0.750000, 1.0 - fTop , 0.875000, 1.0 - fMiddle )
		pTrack.SetFrame(7, 0.875000, 1.0 - fTop , 1.000000, 1.0 - fMiddle )

		fMiddle = fMiddle + 0.125

		pTrack = pContainer.AddTextureTrack(8)

		pTrack.SetFrame(0, 0.000000, 1.0 - fTop , 0.125000, 1.0 - fMiddle )
		pTrack.SetFrame(1, 0.125000, 1.0 - fTop , 0.250000, 1.0 - fMiddle )
		pTrack.SetFrame(2, 0.250000, 1.0 - fTop , 0.375000, 1.0 - fMiddle )
		pTrack.SetFrame(3, 0.375000, 1.0 - fTop , 0.500000, 1.0 - fMiddle )
		pTrack.SetFrame(4, 0.500000, 1.0 - fTop , 0.625000, 1.0 - fMiddle )
		pTrack.SetFrame(5, 0.625000, 1.0 - fTop , 0.750000, 1.0 - fMiddle )
		pTrack.SetFrame(6, 0.750000, 1.0 - fTop , 0.875000, 1.0 - fMiddle )
		pTrack.SetFrame(7, 0.875000, 1.0 - fTop , 1.000000, 1.0 - fMiddle )

		fTop = fTop + 0.125

	pContainer = App.g_kTextureAnimManager.AddContainer("data/Textures/Effects/SunFlaresRed.tga")
	fTop	= 0.125 / 2.0
	fMiddle	= 0.0

	for i in range(8):

		pTrack = pContainer.AddTextureTrack(8)

		pTrack.SetFrame(0, 0.000000, 1.0 - fTop , 0.125000, 1.0 - fMiddle )
		pTrack.SetFrame(1, 0.125000, 1.0 - fTop , 0.250000, 1.0 - fMiddle )
		pTrack.SetFrame(2, 0.250000, 1.0 - fTop , 0.375000, 1.0 - fMiddle )
		pTrack.SetFrame(3, 0.375000, 1.0 - fTop , 0.500000, 1.0 - fMiddle )
		pTrack.SetFrame(4, 0.500000, 1.0 - fTop , 0.625000, 1.0 - fMiddle )
		pTrack.SetFrame(5, 0.625000, 1.0 - fTop , 0.750000, 1.0 - fMiddle )
		pTrack.SetFrame(6, 0.750000, 1.0 - fTop , 0.875000, 1.0 - fMiddle )
		pTrack.SetFrame(7, 0.875000, 1.0 - fTop , 1.000000, 1.0 - fMiddle )

		fMiddle = fMiddle + 0.125

		pTrack = pContainer.AddTextureTrack(8)

		pTrack.SetFrame(0, 0.000000, 1.0 - fTop , 0.125000, 1.0 - fMiddle )
		pTrack.SetFrame(1, 0.125000, 1.0 - fTop , 0.250000, 1.0 - fMiddle )
		pTrack.SetFrame(2, 0.250000, 1.0 - fTop , 0.375000, 1.0 - fMiddle )
		pTrack.SetFrame(3, 0.375000, 1.0 - fTop , 0.500000, 1.0 - fMiddle )
		pTrack.SetFrame(4, 0.500000, 1.0 - fTop , 0.625000, 1.0 - fMiddle )
		pTrack.SetFrame(5, 0.625000, 1.0 - fTop , 0.750000, 1.0 - fMiddle )
		pTrack.SetFrame(6, 0.750000, 1.0 - fTop , 0.875000, 1.0 - fMiddle )
		pTrack.SetFrame(7, 0.875000, 1.0 - fTop , 1.000000, 1.0 - fMiddle )

		fTop = fTop + 0.125

	pContainer = App.g_kTextureAnimManager.AddContainer("data/Textures/Effects/SunFlaresRedOrange.tga")
	fTop	= 0.125 / 2.0
	fMiddle	= 0.0

	for i in range(8):

		pTrack = pContainer.AddTextureTrack(8)

		pTrack.SetFrame(0, 0.000000, 1.0 - fTop , 0.125000, 1.0 - fMiddle )
		pTrack.SetFrame(1, 0.125000, 1.0 - fTop , 0.250000, 1.0 - fMiddle )
		pTrack.SetFrame(2, 0.250000, 1.0 - fTop , 0.375000, 1.0 - fMiddle )
		pTrack.SetFrame(3, 0.375000, 1.0 - fTop , 0.500000, 1.0 - fMiddle )
		pTrack.SetFrame(4, 0.500000, 1.0 - fTop , 0.625000, 1.0 - fMiddle )
		pTrack.SetFrame(5, 0.625000, 1.0 - fTop , 0.750000, 1.0 - fMiddle )
		pTrack.SetFrame(6, 0.750000, 1.0 - fTop , 0.875000, 1.0 - fMiddle )
		pTrack.SetFrame(7, 0.875000, 1.0 - fTop , 1.000000, 1.0 - fMiddle )

		fMiddle = fMiddle + 0.125

		pTrack = pContainer.AddTextureTrack(8)

		pTrack.SetFrame(0, 0.000000, 1.0 - fTop , 0.125000, 1.0 - fMiddle )
		pTrack.SetFrame(1, 0.125000, 1.0 - fTop , 0.250000, 1.0 - fMiddle )
		pTrack.SetFrame(2, 0.250000, 1.0 - fTop , 0.375000, 1.0 - fMiddle )
		pTrack.SetFrame(3, 0.375000, 1.0 - fTop , 0.500000, 1.0 - fMiddle )
		pTrack.SetFrame(4, 0.500000, 1.0 - fTop , 0.625000, 1.0 - fMiddle )
		pTrack.SetFrame(5, 0.625000, 1.0 - fTop , 0.750000, 1.0 - fMiddle )
		pTrack.SetFrame(6, 0.750000, 1.0 - fTop , 0.875000, 1.0 - fMiddle )
		pTrack.SetFrame(7, 0.875000, 1.0 - fTop , 1.000000, 1.0 - fMiddle )

		fTop = fTop + 0.125

	pContainer = App.g_kTextureAnimManager.AddContainer("data/Textures/Effects/SunFlaresBlue.tga")
	fTop	= 0.125 / 2.0
	fMiddle	= 0.0

	for i in range(8):

		pTrack = pContainer.AddTextureTrack(8)

		pTrack.SetFrame(0, 0.000000, 1.0 - fTop , 0.125000, 1.0 - fMiddle )
		pTrack.SetFrame(1, 0.125000, 1.0 - fTop , 0.250000, 1.0 - fMiddle )
		pTrack.SetFrame(2, 0.250000, 1.0 - fTop , 0.375000, 1.0 - fMiddle )
		pTrack.SetFrame(3, 0.375000, 1.0 - fTop , 0.500000, 1.0 - fMiddle )
		pTrack.SetFrame(4, 0.500000, 1.0 - fTop , 0.625000, 1.0 - fMiddle )
		pTrack.SetFrame(5, 0.625000, 1.0 - fTop , 0.750000, 1.0 - fMiddle )
		pTrack.SetFrame(6, 0.750000, 1.0 - fTop , 0.875000, 1.0 - fMiddle )
		pTrack.SetFrame(7, 0.875000, 1.0 - fTop , 1.000000, 1.0 - fMiddle )

		fMiddle = fMiddle + 0.125

		pTrack = pContainer.AddTextureTrack(8)

		pTrack.SetFrame(0, 0.000000, 1.0 - fTop , 0.125000, 1.0 - fMiddle )
		pTrack.SetFrame(1, 0.125000, 1.0 - fTop , 0.250000, 1.0 - fMiddle )
		pTrack.SetFrame(2, 0.250000, 1.0 - fTop , 0.375000, 1.0 - fMiddle )
		pTrack.SetFrame(3, 0.375000, 1.0 - fTop , 0.500000, 1.0 - fMiddle )
		pTrack.SetFrame(4, 0.500000, 1.0 - fTop , 0.625000, 1.0 - fMiddle )
		pTrack.SetFrame(5, 0.625000, 1.0 - fTop , 0.750000, 1.0 - fMiddle )
		pTrack.SetFrame(6, 0.750000, 1.0 - fTop , 0.875000, 1.0 - fMiddle )
		pTrack.SetFrame(7, 0.875000, 1.0 - fTop , 1.000000, 1.0 - fMiddle )

		fTop = fTop + 0.125

	pContainer = App.g_kTextureAnimManager.AddContainer("data/Textures/Effects/SunFlaresWhite.tga")
	fTop	= 0.125 / 2.0
	fMiddle	= 0.0

	for i in range(8):

		pTrack = pContainer.AddTextureTrack(8)

		pTrack.SetFrame(0, 0.000000, 1.0 - fTop , 0.125000, 1.0 - fMiddle )
		pTrack.SetFrame(1, 0.125000, 1.0 - fTop , 0.250000, 1.0 - fMiddle )
		pTrack.SetFrame(2, 0.250000, 1.0 - fTop , 0.375000, 1.0 - fMiddle )
		pTrack.SetFrame(3, 0.375000, 1.0 - fTop , 0.500000, 1.0 - fMiddle )
		pTrack.SetFrame(4, 0.500000, 1.0 - fTop , 0.625000, 1.0 - fMiddle )
		pTrack.SetFrame(5, 0.625000, 1.0 - fTop , 0.750000, 1.0 - fMiddle )
		pTrack.SetFrame(6, 0.750000, 1.0 - fTop , 0.875000, 1.0 - fMiddle )
		pTrack.SetFrame(7, 0.875000, 1.0 - fTop , 1.000000, 1.0 - fMiddle )

		fMiddle = fMiddle + 0.125

		pTrack = pContainer.AddTextureTrack(8)

		pTrack.SetFrame(0, 0.000000, 1.0 - fTop , 0.125000, 1.0 - fMiddle )
		pTrack.SetFrame(1, 0.125000, 1.0 - fTop , 0.250000, 1.0 - fMiddle )
		pTrack.SetFrame(2, 0.250000, 1.0 - fTop , 0.375000, 1.0 - fMiddle )
		pTrack.SetFrame(3, 0.375000, 1.0 - fTop , 0.500000, 1.0 - fMiddle )
		pTrack.SetFrame(4, 0.500000, 1.0 - fTop , 0.625000, 1.0 - fMiddle )
		pTrack.SetFrame(5, 0.625000, 1.0 - fTop , 0.750000, 1.0 - fMiddle )
		pTrack.SetFrame(6, 0.750000, 1.0 - fTop , 0.875000, 1.0 - fMiddle )
		pTrack.SetFrame(7, 0.875000, 1.0 - fTop , 1.000000, 1.0 - fMiddle )

		fTop = fTop + 0.125

	pContainer = App.g_kTextureAnimManager.AddContainer("data/Textures/Effects/SunFlaresYellow.tga")
	fTop	= 0.125 / 2.0
	fMiddle	= 0.0

	for i in range(8):

		pTrack = pContainer.AddTextureTrack(8)

		pTrack.SetFrame(0, 0.000000, 1.0 - fTop , 0.125000, 1.0 - fMiddle )
		pTrack.SetFrame(1, 0.125000, 1.0 - fTop , 0.250000, 1.0 - fMiddle )
		pTrack.SetFrame(2, 0.250000, 1.0 - fTop , 0.375000, 1.0 - fMiddle )
		pTrack.SetFrame(3, 0.375000, 1.0 - fTop , 0.500000, 1.0 - fMiddle )
		pTrack.SetFrame(4, 0.500000, 1.0 - fTop , 0.625000, 1.0 - fMiddle )
		pTrack.SetFrame(5, 0.625000, 1.0 - fTop , 0.750000, 1.0 - fMiddle )
		pTrack.SetFrame(6, 0.750000, 1.0 - fTop , 0.875000, 1.0 - fMiddle )
		pTrack.SetFrame(7, 0.875000, 1.0 - fTop , 1.000000, 1.0 - fMiddle )

		fMiddle = fMiddle + 0.125

		pTrack = pContainer.AddTextureTrack(8)

		pTrack.SetFrame(0, 0.000000, 1.0 - fTop , 0.125000, 1.0 - fMiddle )
		pTrack.SetFrame(1, 0.125000, 1.0 - fTop , 0.250000, 1.0 - fMiddle )
		pTrack.SetFrame(2, 0.250000, 1.0 - fTop , 0.375000, 1.0 - fMiddle )
		pTrack.SetFrame(3, 0.375000, 1.0 - fTop , 0.500000, 1.0 - fMiddle )
		pTrack.SetFrame(4, 0.500000, 1.0 - fTop , 0.625000, 1.0 - fMiddle )
		pTrack.SetFrame(5, 0.625000, 1.0 - fTop , 0.750000, 1.0 - fMiddle )
		pTrack.SetFrame(6, 0.750000, 1.0 - fTop , 0.875000, 1.0 - fMiddle )
		pTrack.SetFrame(7, 0.875000, 1.0 - fTop , 1.000000, 1.0 - fMiddle )

		fTop = fTop + 0.125

def LoadStatic(Icons = None):

	if(Icons is None):
		Icons = App.g_kIconManager.CreateIconGroup("View Screen Static")
		# Add group to manager.
		App.g_kIconManager.AddIconGroup(Icons)

	Icons.LoadIconTexture("data/Textures/Effects/Noise1.tga")
	Icons.LoadIconTexture("data/Textures/Effects/Noise2.tga")
	Icons.LoadIconTexture("data/Textures/Effects/Noise3.tga")

# Load the WarpFlashTextures icon group.
def LoadWarpFlashTextures(Icons = None):
	
	# Setup
	if(Icons is None):
		Icons = App.g_kIconManager.CreateIconGroup("WarpFlashTextures")
		# Add group to manager.
		App.g_kIconManager.AddIconGroup(Icons)

	kTexture = Icons.LoadIconTexture('data/Textures/warpflash1.tga')
	Icons.SetIconLocation(0, kTexture, 0, 0, 64, 64)
	kTexture = Icons.LoadIconTexture('data/Textures/warpflash2.tga')
	Icons.SetIconLocation(1, kTexture, 0, 0, 64, 64)
	kTexture = Icons.LoadIconTexture('data/Textures/warpflash3.tga')
	Icons.SetIconLocation(2, kTexture, 0, 0, 64, 64)
	kTexture = Icons.LoadIconTexture('data/Textures/warpflash4.tga')
	Icons.SetIconLocation(3, kTexture, 0, 0, 64, 64)
	kTexture = Icons.LoadIconTexture('data/Textures/warpflash5.tga')
	Icons.SetIconLocation(4, kTexture, 0, 0, 64, 64)
	kTexture = Icons.LoadIconTexture('data/Textures/warpflash6.tga')
	Icons.SetIconLocation(5, kTexture, 0, 0, 64, 64)
	kTexture = Icons.LoadIconTexture('data/Textures/warpflash7.tga')
	Icons.SetIconLocation(6, kTexture, 0, 0, 64, 64)
	kTexture = Icons.LoadIconTexture('data/Textures/warpflash8.tga')
	Icons.SetIconLocation(7, kTexture, 0, 0, 64, 64)

def LoadDamageTextures(Icons = None):
	
	if(Icons is None):
		Icons = App.g_kIconManager.CreateIconGroup("DamageTextures")
		App.g_kIconManager.AddIconGroup(Icons)

	kTexture = Icons.LoadIconTexture('data/Damage1.tga')
	Icons.SetIconLocation(0, kTexture, 0, 0, 64, 64)
	kTexture = Icons.LoadIconTexture('data/Damage2.tga')
	Icons.SetIconLocation(1, kTexture, 0, 0, 64, 64)
	kTexture = Icons.LoadIconTexture('data/Damage3.tga')
	Icons.SetIconLocation(2, kTexture, 0, 0, 64, 64)
	kTexture = Icons.LoadIconTexture('data/Damage4.tga')
	Icons.SetIconLocation(3, kTexture, 0, 0, 64, 64)

