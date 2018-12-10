import os


__author__ = "d00rt - @D00RT_RM"

__version__ = "1.0.0"
__maintainer__ = "d00rt - @D00RT_RM"
__email__ = "d00rt.fake@gmail.com"
__status__ = "Testing"


DIR_CURRENT             = os.path.dirname(__file__)

DIR_YARA                = os.path.join(DIR_CURRENT, "yara")
DIR_DUMPS               = os.path.join(DIR_CURRENT, "dumps")
DIR_OUTPUT              = os.path.join(DIR_CURRENT, "output")

FOLDER_EXTRACTED_FILES  = "extracted_files"
DIR_EXTRACTED_FILES     = os.path.join(DIR_OUTPUT, FOLDER_EXTRACTED_FILES)

FOLDER_LAYER_2			= "layer2"
FOLDER_PAYLOAD			= "broken_payload"

DIR_LAYER_2			    = os.path.join(DIR_EXTRACTED_FILES, FOLDER_LAYER_2)
DIR_PAYLOAD			    = os.path.join(DIR_EXTRACTED_FILES, FOLDER_PAYLOAD)

FOLDER_STATIC_CONFIG    = "static_configuration"
DIR_STATIC_CONFIG       = os.path.join(DIR_OUTPUT, FOLDER_STATIC_CONFIG)

FOLDER_UNPACKED_FILES   = "unpacked"
DIR_UNPACKED_FILES      = os.path.join(DIR_OUTPUT, FOLDER_UNPACKED_FILES)

FILE_YARA_RSA           = os.path.join(DIR_YARA, "emotet_rsa_key.yar")
FILE_YARA_CODE          = os.path.join(DIR_YARA, "emotet_code.yar")
FILE_YARA_HOOKS         = os.path.join(DIR_YARA, "hooks.yar")

FILE_IPS                = "ips.txt"
FILE_RSA                = "rsa.txt"
FILE_LAYER_2            = "layer2"
FILE_PAYLOAD            = "broken_payload"

FILE_EMOTET             = "unpacked"