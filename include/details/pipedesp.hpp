/*
 * =====================================================================================
 *
 *       Filename: pipedesp.hpp
 *        Created: 01/16/2019 22:43:24
 *    Description: 
 *
 *        Version: 1.0
 *       Revision: none
 *       Compiler: gcc
 *
 *         Author: ANHONG
 *          Email: anhonghe@gmail.com
 *   Organization: USTC
 *
 * =====================================================================================
 */

struct pipe_desp
{
#if defined(_WIN32)
    HANDLE desp    = nullptr;
    bool   inherit = true;
#else
    int    desp = -1;
#endif
};
