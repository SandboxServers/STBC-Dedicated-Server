# C:\Utopia\Current\Build\scripts\ships\Hardpoints\bombfreighter.py
# This file was automatically generated - modify at your own risk.
# 

import App
import GlobalPropertyTemplates
	# The line below is needed by the editor to restore
	# the name of the parent script.
ParentPropertyScript = "ships.Hardpoints.cardfreighter"
if not ('g_bIsModelPropertyEditor' in dir(App)):
	ParentModule = __import__("ships.Hardpoints.cardfreighter", globals(), locals(), ['*'])
	reload(ParentModule)
# Setting up local templates.
#################################################
CargoHold = App.HullProperty_Create("Cargo Hold")

CargoHold.SetMaxCondition(700.000000)
CargoHold.SetCritical(1)
CargoHold.SetTargetable(1)
CargoHold.SetPrimary(0)
CargoHold.SetPosition(0.000000, -0.420000, 0.100000)
CargoHold.SetPosition2D(64.000000, 75.000000)
CargoHold.SetRepairComplexity(6.000000)
CargoHold.SetDisabledPercentage(0.000000)
CargoHold.SetRadius(0.230000)
App.g_kModelPropertyManager.RegisterLocalTemplate(CargoHold)

# Property load function.
def LoadPropertySet(pObj):
	"Sets up the object's properties."
	if not ('g_bIsModelPropertyEditor' in dir(App)):
		ParentModule.LoadPropertySet(pObj)
	prop = App.g_kModelPropertyManager.FindByName("Cargo Hold", App.TGModelPropertyManager.LOCAL_TEMPLATES)
	if (prop != None):
		pObj.AddToSet("Scene Root", prop)
