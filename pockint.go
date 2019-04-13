package main

import (
	"fmt"
	"github.com/therecipe/qt/widgets"
	"os"
)

var (
	appVersion = "1.0.0-beta"
	appTitle   = fmt.Sprintf("POCKINT v.%s", appVersion)
)

func main() {

	// needs to be called once before you can start using the QWidgets
	app := widgets.NewQApplication(len(os.Args), os.Args)

	window := widgets.NewQMainWindow(nil, 0)
	window.SetMinimumSize2(450, 200)
	window.SetWindowTitle(appTitle)

	// make the window visible and start main Qt event loop
	window.Show()
	app.Exec()

}
