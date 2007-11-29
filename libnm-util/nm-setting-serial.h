/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef NM_SETTING_SERIAL_H
#define NM_SETTING_SERIAL_H

#include <nm-setting.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_SERIAL            (nm_setting_serial_get_type ())
#define NM_SETTING_SERIAL(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_SERIAL, NMSettingSerial))
#define NM_SETTING_SERIAL_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_SERIAL, NMSettingSerialClass))
#define NM_IS_SETTING_SERIAL(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_SERIAL))
#define NM_IS_SETTING_SERIAL_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SETTING_SERIAL))
#define NM_SETTING_SERIAL_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_SERIAL, NMSettingSerialClass))

#define NM_SETTING_SERIAL_SETTING_NAME "serial"

#define NM_SETTING_SERIAL_BAUD "baud"
#define NM_SETTING_SERIAL_BITS "bits"
#define NM_SETTING_SERIAL_PARITY "parity"
#define NM_SETTING_SERIAL_STOPBITS "stopbits"
#define NM_SETTING_SERIAL_SEND_DELAY "send-delay"

typedef struct {
	NMSetting parent;

	guint baud;
	guint bits;
	char parity;
	guint stopbits;
	guint64 send_delay;
} NMSettingSerial;

typedef struct {
	NMSettingClass parent;
} NMSettingSerialClass;

GType nm_setting_serial_get_type (void);

NMSetting *nm_setting_serial_new (void);

G_END_DECLS

#endif /* NM_SETTING_SERIAL_H */
