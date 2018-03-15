from jsonschema import Draft3Validator

"""
Defines the schema responses expected from IDP/FMS/Atlas/RD
Can be used to check json response is correctly formatted
"""

ASK_URL_RESPONSE = {
    "title": "Atlas Temp URL Info",
    "type": "object",
    "properties":
    {
        "tempURL": {
            "type": "string",
            "minLength": 1,
            "maxLength": 2000
        },
        "userId": {
            "type": "string",
            "minLength": 1,
            "maxLength": 1000
        },
        "logFilename": {
            "type": "string",
            "minLength": 1,
            "maxLength": 1000
        },
    },
    "required": ["tempURL", "userId", "logFilename"],
}

BEARER_TOKEN_RESPONSE = {
    "title": "Bearer Token Response",
    "type": "object",
    "properties": 
    {
        "BearerToken": {
            "type": "string",
            "minLength": 1,
            "maxLength": 100000 
        }
    },
    "required": ["BearerToken"],
}

MACHINE_ACCOUNT_RESPONSE = {
    "title": "OAUTH Machine Account Response",
    "type": "object",
    "properties":
    {
        "email": {
            "type": "string",
            "minLength": 1,
            "maxLength": 1000
        },
        "entitlements": {
            "type": "array",
            "items": {
                "type": "string"
            }
        },
        "id": {
            "type": "string",
            "minLength": 1,
            "maxLength": 1000
        },
        "machineType": {
            "type": "string",
            "minLength": 1,
            "maxLength": 1000
        },
        "name": {
            "type": "string",
            "minLength": 1,
            "maxLength": 1000
        },
        "schemas": {
            "type": "array",
            "items": {
                "type": "string"
            }
        },
    },
    "required": ["id", "name"]
}

ACCESS_TOKEN_RESPONSE = {
    "title": "Access Token Response",
    "type": "object",
    "properties": 
    {
        "access_token": {
            "type": "string", 
            "minLength": 1,
            "maxLength": 100000 
        },
        "expires_in": {
            "type": "integer",
            "minLength": 1,
            "maxLength": 100
        },
        "refresh_token": { 
            "type": "string", 
            "minLength": 1,
            "maxLength": 100000 
        },
        "refresh_token_expires_in": {
            "type": "integer",
            "minLength": 1,
            "maxLength": 100
        }
    },
    "required": ["access_token", "refresh_token"],
}

REFRESH_ACCESS_TOKEN_RESPONSE = {
    "title": "Access Token Response",
    "type": "object",
    "properties": 
    {
        "access_token": {
            "type": "string", 
            "minLength": 1,
            "maxLength": 100000 
        },
        "expires_in": {
            "type": "integer",
            "minLength": 1,
            "maxLength": 100
        },
        "accountExpiration": {
            "type": "integer",
            "minLength": 1,
            "maxLength": 100
        }
    },
    "required": ["access_token", "expires_in"],
}

MANAGEMENT_CONNECTOR_REGISTER_RESPONSE = {
    "title": "Management Connector Register Response",
    "type": "object",
    "properties": {
        "display_name": {
            "type": "string",
            "minLength": 1,
            "maxLength": 256 
            },
        "connector_type": {
            "type": "string",
            "minLength": 1,
            "maxLength": 20 
            },
        "version": {
            "type": "string", 
            "minLength": 1,
            "maxLength": 100
            },
        "provisioning": {
            "type": "object",
            "properties": {
                "connectors": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "display_name": {
                                "type": "string",
                                "minLength": 1,
                                "maxLength": 256 
                            },
                            "connector_type": {
                                "type": "string",
                                "minLength": 1,
                                "maxLength": 20 
                            },
                            "packages": {
                                "type": "array",
                                "items": {
                                    "type": ["object", "null", "array"]
                                }
                            }
                        }
                    }
                }
            }
        },
        "dependencies": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "tlpUrl": {
                        "type": "string",
                        "pattern": "[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*)",
                        "minLength": 1,
                        "maxLength": 2048 },
                    "dependencyType": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 10,
                        "pattern": "^[A-Za-z0-9_]+$" },
                    "version": {
                        "type": "string",
                        "minLength": 0,
                        "maxLength": 100 }
                },
                "required": ["tlpUrl", "dependencyType", "version"]
            }
        },
        "heartbeatInterval": {
            "type": "integer",
            "minLength": 1,
            "maxLength": 10
        }        
    },
    "required": ["provisioning"]
}

WDM_RESPONSE = {
    "title": "Device Manager Response",
    "type": "object",
    "properties":
    {
        "url": {
            "type": "string",
            "minLength": 1,
            "maxLength": 2048
        },
        "webSocketUrl": {
            "type": "string",
            "minLength": 1,
            "maxLength": 2048
        }
    },
    "required": ["url", "webSocketUrl"],
}

MERCURY_MESSAGE = {
    "title": "Mercury WS Message",
    "type": "object",
    "properties": {
        "data": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 2048
                        },
                        "commandId": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 2048
                        },
                    },
                    "required": ["action" , "commandId"]
                },
                "signature": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 2048
                },
                "eventType": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 2048
                }
            },
            "required": ["command", "signature", "eventType"]
            }
        },
    "required": ["data"]
}

MERCURY_PROBE_MESSAGE = {
    "title": "Mercury Probe Message",
    "type": "object",
    "properties": {
        "data": {
            "type": "object",
            "properties": {
                "eventType": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 2048
                }
            },
            "required": ["eventType"]
        }
    }
}

FEATURES_TOGGLE_RESPONSE = {
    "title": "Feature Toggle Response",
    "type": "object",
    "properties":
    {
        "developer": {
            "type": "array",
            "items": {
                "type": ["object", "null", "array"]
            }
        }
    },
    "required": ["developer"]
}

REMOTE_DISPATCHER_RESPONSE = {
    "title": "Remote Dispatcher Response",
    "type": "object",
    "properties":
    {
        "clusterName": {
            "type": "string",
            "maxLength": 255
        },
        "connectorId": {
            "type": "string",
            "minLength": 1,
            "maxLength": 80
        },
        "connectorType": {
            "type": "string",
            "minLength": 1,
            "maxLength": 80
        },
        "hostname": {
            "type": "string",
            "minLength": 1,
            "maxLength": 63
        },
        "clusterId": {
            "type": "string",
            "minLength": 1,
            "maxLength": 80
        },
        "orgId": {
            "type": "string",
            "minLength": 1,
            "maxLength": 80
        },
        "deviceId": {
            "type": "string",
            "minLength": 1,
            "maxLength": 80
        }
    },
    "required": ["clusterName", "connectorId", "hostname", "clusterId", "orgId", "deviceId"]
}

U2C_SERVICES_RESPONSE = {
    "title": "U2C Service Response",
    "type": "object",
    "properties": {
        "services": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                            "serviceName": {
                                "type": "string",
                                "minLength": 1,
                                "maxLength": 256
                            },
                            "logicalNames": {
                                "type": "array",
                                "items": {
                                    "type": "string"
                                }
                            }
                },
                "required": ["serviceName", "logicalNames"]
            }
        }
    },
    "required": ["services"]
}

HYBRID_REQUEST_SCHEMA = {
    "title": "Hybrid Request Schema",
    "type": "object",
    "properties":
    {
        "connector": {
            "type": "string",
            "minLength": 1,
            "maxLength": 80
        },
        "request": {
            "type": "string",
            "minLength": 1,
            "maxLength": 80
        },
        "value": {
            "type": ["string", "boolean"],
            "minLength": 1,
            "maxLength": 80
        },
    },
    "required": ["connector", "request", "value"]
}
