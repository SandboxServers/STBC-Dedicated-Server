# DamageIcons.py
#
# Load Ship Damage Icons for interface.
# 
#

import App

# Function to load LCARS icon group
def LoadDamageIcons(DamageIcons = None):
	
	if DamageIcons is None:
		DamageIcons = App.g_kIconManager.CreateIconGroup("DamageIcons")
		# Add DamgeIcons icon group to IconManager
		App.g_kIconManager.AddIconGroup(DamageIcons)
	
	# Icon numbers should match up with DamageIcon::DamageIcons enum.
	# Hull
	kTextureHandle = DamageIcons.LoadIconTexture('Data/Icons/Damage/Hull.tga')
	DamageIcons.SetIconLocation(0, kTextureHandle, 0, 0, 16, 16)

	# Impulse engines
	kTextureHandle = DamageIcons.LoadIconTexture('Data/Icons/Damage/Impulse.tga')
	DamageIcons.SetIconLocation(1, kTextureHandle, 0, 0, 16, 16)

	# Phaser
	kTextureHandle = DamageIcons.LoadIconTexture('Data/Icons/Damage/Phaser.tga')
	DamageIcons.SetIconLocation(2, kTextureHandle, 0, 0, 16, 16)

	# Power
	kTextureHandle = DamageIcons.LoadIconTexture('Data/Icons/Damage/Power.tga')
	DamageIcons.SetIconLocation(3, kTextureHandle, 0, 0, 16, 16)
	
	# Sensor
	kTextureHandle = DamageIcons.LoadIconTexture('Data/Icons/Damage/Sensor.tga')
	DamageIcons.SetIconLocation(4, kTextureHandle, 0, 0, 16, 16)

	# Shield
	kTextureHandle = DamageIcons.LoadIconTexture('Data/Icons/Damage/Shield.tga')
	DamageIcons.SetIconLocation(5, kTextureHandle, 0, 0, 16, 16)

	# Unknown system
	kTextureHandle = DamageIcons.LoadIconTexture('Data/Icons/Damage/System.tga')
	DamageIcons.SetIconLocation(6, kTextureHandle, 0, 0, 16, 16)

	# Torpedo
	kTextureHandle = DamageIcons.LoadIconTexture('Data/Icons/Damage/Torpedo.tga')
	DamageIcons.SetIconLocation(7, kTextureHandle, 0, 0, 16, 16)

	# Warp
	kTextureHandle = DamageIcons.LoadIconTexture('Data/Icons/Damage/Warp.tga')
	DamageIcons.SetIconLocation(8, kTextureHandle, 0, 0, 16, 16)

	# Disruptor Cannon
	kTextureHandle = DamageIcons.LoadIconTexture('Data/Icons/Damage/Disruptor.tga')
	DamageIcons.SetIconLocation(9, kTextureHandle, 0, 0, 16, 16)
