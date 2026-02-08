###############################################################################
#	Filename:	TacticalIcons.py
#	
#	Confidential and Proprietary, Copyright 2000 by Totally Games
#	
#	Script for loading icons used in tactical and in combat.
#	
#	Created:	11/3/00 -	Erik Novales
###############################################################################

import App

#kDebugObj = App.CPyDebug()

App.g_kIconManager.RegisterIconGroup("EffectTextures", "Tactical.EffectTextures", "LoadEffectTextures")
App.g_kIconManager.RegisterIconGroup("View Screen Static", "Tactical.EffectTextures", "LoadStatic")
App.g_kIconManager.RegisterIconGroup("WarpFlashTextures", "Tactical.EffectTextures", "LoadWarpFlashTextures")
App.g_kIconManager.RegisterIconGroup("DamageTextures", "Tactical.EffectTextures", "LoadDamageTextures")
App.g_kIconManager.RegisterIconGroup("ReticleTextures", "Tactical.ReticleTextures", "LoadReticleTextures")

# Force it to load right away
App.g_kIconManager.GetIconGroup("EffectTextures")
App.g_kIconManager.GetIconGroup("WarpFlashTextures")
App.g_kIconManager.GetIconGroup("DamageTextures")