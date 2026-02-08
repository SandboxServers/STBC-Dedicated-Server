import App

# This script adds visual damage to an object
def AddDamage(pThingToDamage):
	pThingToDamage.AddObjectDamageVolume(0.228382, 0.971922, 0.156499, 1.000000, 600.000000)
	pThingToDamage.AddObjectDamageVolume(1.090698, -0.248390, -0.008415, 1.000000, 600.000000)
	pThingToDamage.AddObjectDamageVolume(-0.058236, -0.938884, 0.081909, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(-0.058236, -0.938884, 0.081908, 1.000000, 600.000000)
	pThingToDamage.AddObjectDamageVolume(0.022176, -2.081851, 0.126606, 1.000000, 600.000000)
	pThingToDamage.AddObjectDamageVolume(0.101528, -2.327002, 0.126547, 1.000000, 600.000000)
	pThingToDamage.AddObjectDamageVolume(-0.293311, 0.697177, 0.181383, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(-0.121439, -0.086482, 0.144393, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(-0.121439, -0.086482, 0.144393, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(-0.094818, 0.017219, -0.266692, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(-0.176207, 0.060370, -0.268201, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(-0.176207, 0.060370, -0.268201, 0.400000, 300.000000)
	pThingToDamage.AddObjectDamageVolume(-0.669773, -0.373498, -0.016145, 1.000000, 600.000000)
	pThingToDamage.DamageRefresh(1)
