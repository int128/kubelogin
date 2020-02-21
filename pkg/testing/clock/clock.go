package clock

import "time"

type Fake time.Time

func (f Fake) Now() time.Time {
	return time.Time(f)
}
