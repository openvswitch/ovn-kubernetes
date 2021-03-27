package metrics

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	kapi "k8s.io/api/core/v1"
)

var metricServiceCount = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: MetricOvnNamespace,
	Subsystem: MetricOvnSubsystemController,
	Name:      "service_count",
	Help: "Metric that specifies the number of services by their type. " +
		"Type of the service is specified with the label type.",
},
	[]string{
		"type",
	},
)

type ServiceMetrics interface {
	Increment(service *kapi.Service)
	Decrement(service *kapi.Service)
	GetAll() map[kapi.ServiceType]uint64
}

type serviceMetricsData struct {
	sync.RWMutex
	metricsMap map[kapi.ServiceType]uint64
}

var serviceMetrics ServiceMetrics = &serviceMetricsData{metricsMap: make(map[kapi.ServiceType]uint64)}

func GetServiceMetricsInstance() ServiceMetrics {
	return serviceMetrics
}

func (s *serviceMetricsData) Increment(service *kapi.Service) {
	s.Lock()
	defer s.Unlock()
	if s.metricsMap[service.Spec.Type] < ^uint64(0) {
		s.metricsMap[service.Spec.Type]++
	}
}

func (s *serviceMetricsData) Decrement(service *kapi.Service) {
	s.Lock()
	defer s.Unlock()
	if s.metricsMap[service.Spec.Type] > 0 {
		s.metricsMap[service.Spec.Type]--
	}
}

func (s *serviceMetricsData) GetAll() map[kapi.ServiceType]uint64 {
	localMetricsMap := make(map[kapi.ServiceType]uint64)
	s.RLock()
	defer s.RUnlock()
	for key, value := range s.metricsMap {
		localMetricsMap[key] = value
	}
	return localMetricsMap
}

func serviceMetricsUpdater() {
	ovnRegistry.MustRegister(metricServiceCount)
	for {
		setServiceMetrics()
		time.Sleep(delayInSeconds * time.Second)
	}
}

func setServiceMetrics() {
	metricsService := GetServiceMetricsInstance()
	serviceMetrics := metricsService.GetAll()
	for key, value := range serviceMetrics {
		metricServiceCount.WithLabelValues(string(key)).Set(float64(value))
	}
}
