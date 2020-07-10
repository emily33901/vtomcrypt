#ifdef byte
#undef byte
#endif

// These arent defined
// normally in C that would be fine but since V 
// makes sure that all referenced C funcitons actually exist
// we need to put them here
int s_read_arc4random(void *p, size_t n) {}
int s_read_getrandom(void *p, size_t n) {}
int s_read_urandom(void *p, size_t n) {}
int s_read_ltm_rng(void *p, size_t n) {}