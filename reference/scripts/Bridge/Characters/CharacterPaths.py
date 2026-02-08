###############################################################################
#	Filename:	CharacterPaths.py
#	
#	Confidential and Proprietary, Copyright 2001 by Totally Games
#	
#	Set up common paths for head and body textures
#	
#	Created:	8/3/2001 -	Yossi Horowitz
###############################################################################

import App

g_pcNIFDetail = [ "/", "/", "/" ]		# we don't have med and low .nifs
g_pcTexDetail = [ "Low/", "Med/", "/" ]
g_pcRootPath = "data/Models/Characters/"

g_pcBodyNIFPath = None
g_pcHeadNIFPath = None
g_pcBodyTexPath = None
g_pcHeadTexPath = None

def UpdatePaths():
	global g_pcNIFDetail, g_pcTexDetail, g_pcRootPath
	global g_pcBodyNIFPath, g_pcHeadNIFPath, g_pcBodyTexPath, g_pcHeadTexPath

	iDetail = App.g_kImageManager.GetImageDetail()
	g_pcBodyNIFPath = g_pcRootPath + "Bodies" + g_pcNIFDetail[iDetail]
	g_pcHeadNIFPath = g_pcRootPath + "Heads" + g_pcNIFDetail[iDetail]
	g_pcBodyTexPath = g_pcRootPath + "Bodies" + g_pcTexDetail[iDetail]
	g_pcHeadTexPath = g_pcRootPath + "Heads" + g_pcTexDetail[iDetail]

