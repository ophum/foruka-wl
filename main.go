package main

import (
	"fmt"
	"net/http"
	"github.com/pkg/errors"
	"strconv"

	"github.com/coreos/go-iptables/iptables"
	"github.com/gin-gonic/gin"
)

type WhiteList struct {
	AcceptList map[uint16][]Accept `json:"list"`
}
func main() {
	r := gin.Default()
	w := WhiteList{
		AcceptList: map[uint16][]Accept{},
	}

	r.GET("/", w.List)
	r.POST("/", w.Add)
	r.DELETE("/", w.Del)

	r.Run(":8080")
}

type Accept struct {
	SourceIPRange string `json:"sourceIPRange"`
	DestPort uint16 `json:"destPort"`
}

func (w *WhiteList) List(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, w)
}

func (w *WhiteList) Add(ctx *gin.Context) {
	var accept Accept
	err := ctx.Bind(&accept)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{})
		return
	}


	ipt, err := iptables.New()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"err": errors.Wrapf(err, "error iptable.New").Error()})
		return
	}

	rule := getRule(&accept)
	if exists, err := ipt.Exists("filter", "INPUT", rule...); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"err": errors.Wrapf(err, "error iptables exists").Error()})
		return
	} else if exists {
		ctx.JSON(http.StatusFound, gin.H{})
		return
	}

	if err := ipt.Insert("filter", "INPUT", 1, rule...); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"err": errors.Wrapf(err, "error iptables insert").Error()})
		return
	}

	w.AcceptList[accept.DestPort] = append(w.AcceptList[accept.DestPort], accept)

	ctx.JSON(http.StatusCreated, gin.H{})
}

func (w *WhiteList) Del(ctx *gin.Context) {
	portString := ctx.Param("destPort")
	sourceIPRange := ctx.Param("sourceIPRange")
	port64, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{})
		return
	}
	port := uint16(port64)
	accepts, ok := w.AcceptList[port]
	if !ok {
		ctx.JSON(http.StatusNotFound, gin.H{})
		return
	}

	index := -1
	for i, a := range accepts {
		if a.SourceIPRange == sourceIPRange {
			index = i
			break
		}
	}

	if index == -1 {
		ctx.JSON(http.StatusNotFound, gin.H{})
		return
	}
	accept := w.AcceptList[port][index]

	rule := getRule(&accept)

	ipt, err := iptables.New()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{})
		return
	}

	if exists, err := ipt.Exists("filter", "INPUT", rule...); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{})
		return
	} else if !exists {
		w.AcceptList[port] = append(w.AcceptList[port][:index], w.AcceptList[port][index+1:]...)
		ctx.JSON(http.StatusNotFound, gin.H{})
		return
	}

	if err := ipt.Delete("filter", "INPUT", rule...); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{})
		return
	}

	w.AcceptList[port] = append(w.AcceptList[port][:index], w.AcceptList[port][index+1:]...)

	ctx.JSON(http.StatusOK, gin.H{})
}

func getRule(accept *Accept) []string {
	rule := []string{
		"-p", "tcp",
	}

	if accept.SourceIPRange != "" {
		rule = append(rule, []string{
			"-s", accept.SourceIPRange,
		}...)
	}

	rule = append(rule, []string{
		"--dport", fmt.Sprintf("%d", accept.DestPort),
		"-j", "ACCEPT",
	}...)

	return rule
}
