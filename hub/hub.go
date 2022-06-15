package hub

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/google/uuid"
)

type Hub struct {
	sync.Mutex
	ID                string
	writer            *threadSafeWriter
	handlers          map[string][]*handler
	requests          map[uint32]*ClientRequest
	nextTransactionId uint32
}

type handler struct {
	Handler func(ResponseWriter, *Request) error
}

type Writer interface {
	WriteJSON(interface{}) error
}

type Transaction struct {
	ID uint32
}

type Request struct {
	Hub     *Hub
	Method  string
	TxID    uint32
	Payload interface{}
}

type ClientRequest struct {
	Request
	responseHandler func(interface{}, error)
}

type ResponseWriter interface {
	Write(interface{}) error
}

type message struct {
	Method       *string     `json:"method,omitempty"`
	RequestTxID  *uint32     `json:"itx,omitempty"`
	ResponseTxID *uint32     `json:"otx,omitempty"`
	Error        *string     `json:"error,omitempty"`
	Payload      interface{} `json:"payload,omitempty"`
}

func NewHub(writer Writer) *Hub {
	w := &threadSafeWriter{writer, sync.Mutex{}}

	return &Hub{
		sync.Mutex{},
		uuid.NewString(),
		w,
		map[string][]*handler{},
		map[uint32]*ClientRequest{},
		0,
	}
}

func (h *Hub) Request(method string, payload interface{}, handler func(interface{}, error)) error {
	txID := h.nextTransactionId
	h.nextTransactionId++

	msg := message{
		Method:      &method,
		RequestTxID: &txID,
		Payload:     payload,
	}

	h.Lock()
	h.requests[txID] = &ClientRequest{
		Request: Request{
			Hub:     h,
			Method:  method,
			TxID:    txID,
			Payload: payload,
		},
		responseHandler: handler,
	}
	h.Unlock()

	return h.writer.WriteJSON(msg)
}

func (h *Hub) RequestWithoutResponse(method string, payload interface{}) error {
	return h.Request(method, payload, func(_ interface{}, _ error) {})
}

type response struct {
	response interface{}
	err      error
}

func (h *Hub) RequestSync(method string, payload interface{}) (interface{}, error) {
	ch := make(chan response)
	defer close(ch)
	h.Request(method, payload, func(res interface{}, err error) {
		ch <- response{
			response: res,
			err:      err,
		}
	})
	res := <-ch
	return res.response, res.err
}

func (h *Hub) Handle(method string, handlerFn func(ResponseWriter, *Request) error) func() {
	h.Lock()
	defer h.Unlock()

	handlers, ok := h.handlers[method]

	if !ok {
		handlers = []*handler{}
		h.handlers[method] = handlers
	}

	handlerPtr := &handler{
		Handler: handlerFn,
	}

	h.handlers[method] = append(handlers, handlerPtr)

	return func() {
		h.Lock()
		defer h.Unlock()

		handlers := h.handlers[method]

		for i, _handler := range handlers {
			if _handler == handlerPtr {
				h.handlers[method] = append(handlers[:i], handlers[i+1:]...)
			}
		}
	}
}

func (h *Hub) ProcessMessage(bytes []byte) error {
	h.Lock()
	defer h.Unlock()

	msg := &message{}
	if err := json.Unmarshal(bytes, msg); err != nil {
		return err
	} else if msg.RequestTxID != nil && msg.ResponseTxID != nil {
		return errors.New("protocol error")
	} else if msg.RequestTxID != nil {
		if msg.Method == nil {
			return errors.New("protocol error")
		} else if handlers, exists := h.handlers[*msg.Method]; !exists {
			return fmt.Errorf("handler does not exist for method \"%v\"", *msg.Method)
		} else {
			request := &Request{
				Hub:     h,
				Method:  *msg.Method,
				TxID:    *msg.RequestTxID,
				Payload: msg.Payload,
			}
			responseWriter := h.newResponseWriter(request)
			go func() {
				for _, handler := range handlers {
					if err := handler.Handler(responseWriter, request); err != nil {
						responseWriter.writeError(err)
						return
					}
				}

				if !responseWriter.written {
					responseWriter.Write(nil)
				}
			}()
			return nil
		}
	} else if msg.ResponseTxID != nil {
		if request, ok := h.requests[*msg.ResponseTxID]; ok {
			var err error
			if msg.Error != nil {
				err = errors.New(*msg.Error)
			}
			delete(h.requests, *msg.ResponseTxID)
			go func() {
				request.responseHandler(msg.Payload, err)
			}()
		}
		return nil
	} else {
		return errors.New("protocol error")
	}
}

func (h *Hub) newResponseWriter(request *Request) *responseWriter {
	return &responseWriter{sync.Mutex{}, request, h, false}
}

type responseWriter struct {
	sync.Mutex
	request *Request
	hub     *Hub
	written bool
}

func (w *responseWriter) Write(response interface{}) error {
	w.Lock()
	defer w.Unlock()

	if w.written {
		return errors.New("response already sent")
	}
	w.written = true

	msg := message{
		ResponseTxID: &w.request.TxID,
		Payload:      response,
	}

	return w.hub.writer.WriteJSON(msg)
}

func (w *responseWriter) writeError(err error) {
	w.Lock()
	defer w.Unlock()

	if w.written {
		return
	}
	w.written = true

	errString := err.Error()

	msg := message{
		ResponseTxID: &w.request.TxID,
		Error:        &errString,
	}

	w.hub.writer.WriteJSON(msg)
}

type threadSafeWriter struct {
	Writer
	sync.Mutex
}

func (t *threadSafeWriter) WriteJSON(v interface{}) error {
	t.Lock()
	defer t.Unlock()

	return t.Writer.WriteJSON(v)
}
