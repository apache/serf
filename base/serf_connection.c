#include "serf.h"

SERF_DECLARE(serf_connection_t *) serf_create_connection(apr_pool_t *pool)
{
    return apr_pcalloc(pool, sizeof(serf_connection_t));
}
