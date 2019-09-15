#ifndef _NETWORK_COMMON_H_
#define _NETWORK_COMMON_H_

#define PORT            2325
#define LEN             49
#define IPADDRLEN       5
#define OCTET_BYTES     8

#define pr_error(err)   do {                                                                            \
                            pr_info("MODULE: %s | VERSION: %s | FUNC: %s() | LINE: %d | ERROR: %d\n",   \
                                    THIS_MODULE->name, THIS_MODULE->version, __func__, __LINE__, err);  \
                        } while (0)

#define pr_banner() do {                                                                        \
                        pr_info("MODULE: %s | VERSION: %s | FUNC: %s() | LINE: %d |\n",         \
                                THIS_MODULE->name, THIS_MODULE->version, __func__, __LINE__);   \
                    } while (0)

#endif
