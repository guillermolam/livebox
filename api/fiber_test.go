package api

import "testing"

func TestParseFTTH_Golden(t *testing.T) {
	ftth, err := parseFTTH(loadTestData(t, "js_infoFtth.js"))
	if err != nil {
		t.Fatal(err)
	}
	if ftth.PhyLink != 1 {
		t.Errorf("PhyLink = %d, want 1", ftth.PhyLink)
	}
	if ftth.RxPower != "-20.655" || ftth.TxPower != "2.554" {
		t.Errorf("power = rx %q tx %q", ftth.RxPower, ftth.TxPower)
	}
	if ftth.Temp != "39.195" || ftth.Volt != "3.280" || ftth.Bias != "9.300" {
		t.Errorf("temp/volt/bias = %q %q %q", ftth.Temp, ftth.Volt, ftth.Bias)
	}
	if want := "MH4RCHXCSV"; ftth.ONTPassword != want {
		t.Errorf("ONTPassword = %q, want %q", ftth.ONTPassword, want)
	}
}

func TestParseFTTH_LastAssignmentWins(t *testing.T) {
	// infoFtth.js first declares an empty object, then assigns the real one.
	raw := `var traciver_status={};
traciver_status={"phy_link":1,"temp":"40","volt":"3.3","bias":"9","tx_power":"2","rx_power":"-21"};`
	ftth, err := parseFTTH(raw)
	if err != nil {
		t.Fatal(err)
	}
	if ftth.PhyLink != 1 || ftth.RxPower != "-21" {
		t.Errorf("ftth = %+v", ftth)
	}

	// With only the empty declaration, the optics are zero (link down).
	ftth, err = parseFTTH("var traciver_status={};")
	if err != nil {
		t.Fatal(err)
	}
	if ftth.PhyLink != 0 {
		t.Errorf("PhyLink = %d, want 0", ftth.PhyLink)
	}
}
