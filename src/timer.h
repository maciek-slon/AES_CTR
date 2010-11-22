/*!
 * \file
 * \brief Simple timer functions
 */
#ifndef TIMER_H_
#define TIMER_H_

#include <time.h>

typedef struct timespec timespec_t;

/*!
 * Restart timer
 */
void timerRestart(timespec_t *timer) {
	clock_gettime(CLOCK_REALTIME, timer);
}

/*!
 * Return elapsed time in seconds
 */
double timerElapsed(timespec_t *timer) {
	timespec_t end_timer;
	clock_gettime(CLOCK_REALTIME, &end_timer);
	double ns = 0.001*0.001*0.001*(end_timer.tv_nsec - timer->tv_nsec);
	return (double)(end_timer.tv_sec - timer->tv_sec + ns);
}

/*!
 * Return elapsed time in seconds and restart timer
 */
double timerElapsedRestart(timespec_t *timer) {
	timespec_t old_timer = *timer;
	clock_gettime(CLOCK_REALTIME, timer);
	double ns = 0.001*0.001*0.001*(timer->tv_nsec - old_timer.tv_nsec);
	return (double)(timer->tv_sec - old_timer.tv_sec + ns);
}

#endif /* TIMER_H_ */
