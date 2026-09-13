#pragma once
#include <fcntl.h>
#include "esp_err.h"
struct esp_vfs_eventfd_config_t{};
#define ESP_VFS_EVENTD_CONFIG_DEFAULT() esp_vfs_eventfd_config_t{}
inline int esp_vfs_eventfd_register(const esp_vfs_eventfd_config_t*){return ESP_OK;}
// Event loops are driven explicitly in these lifecycle tests.
inline int eventfd(unsigned int,int){return open("/dev/null",O_RDWR);}
