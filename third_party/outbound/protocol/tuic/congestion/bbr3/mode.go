package bbr3

// mode is the sender's state-machine state.
type mode int

const (
	modeStartup mode = iota
	modeDrain
	modeProbeBWDown
	modeProbeBWCruise
	modeProbeBWRefill
	modeProbeBWUp
	modeProbeRTT
)

func (m mode) String() string {
	switch m {
	case modeStartup:
		return "STARTUP"
	case modeDrain:
		return "DRAIN"
	case modeProbeBWDown:
		return "PROBE_BW_DOWN"
	case modeProbeBWCruise:
		return "PROBE_BW_CRUISE"
	case modeProbeBWRefill:
		return "PROBE_BW_REFILL"
	case modeProbeBWUp:
		return "PROBE_BW_UP"
	case modeProbeRTT:
		return "PROBE_RTT"
	}
	return "UNKNOWN"
}

// pacingGain returns the pacing gain applied in the given mode.
func (p Params) pacingGain(m mode) float64 {
	switch m {
	case modeStartup:
		return p.HighGain
	case modeDrain:
		return p.DrainGain
	case modeProbeBWUp:
		return p.UpGain
	case modeProbeBWDown:
		return p.DownGain
	case modeProbeRTT:
		return p.ProbeRttGain
	default:
		return p.CruiseGain
	}
}

// advance returns the next mode in the PROBE_BW gain cycle:
// UP -> DOWN -> CRUISE -> REFILL -> UP.
func (m mode) advance() mode {
	switch m {
	case modeProbeBWDown:
		return modeProbeBWCruise
	case modeProbeBWCruise:
		return modeProbeBWRefill
	case modeProbeBWRefill:
		return modeProbeBWUp
	default:
		return modeProbeBWDown
	}
}
