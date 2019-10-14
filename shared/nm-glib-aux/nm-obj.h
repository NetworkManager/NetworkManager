// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#ifndef __NM_OBJ_H__
#define __NM_OBJ_H__

/*****************************************************************************/

#define NM_OBJ_REF_COUNT_STACKINIT (G_MAXINT)

typedef struct _NMObjBaseInst  NMObjBaseInst;
typedef struct _NMObjBaseClass NMObjBaseClass;

struct _NMObjBaseInst {
	/* The first field of NMObjBaseInst is compatible with GObject.
	 * Basically, NMObjBaseInst is an abstract base type of GTypeInstance.
	 *
	 * If you do it right, you may derive a type of NMObjBaseInst as a proper GTypeInstance.
	 * That involves allocating a GType for it, which can be inconvenient because
	 * a GType is dynamically created (and the class can no longer be immutable
	 * memory).
	 *
	 * Even if your implementation of NMObjBaseInst is not a full fledged GType(Instance),
	 * you still can use GTypeInstances in the same context as you can decide based on the
	 * NMObjBaseClass with what kind of object you are dealing with.
	 *
	 * Basically, the only thing NMObjBaseInst gives you is access to an
	 * NMObjBaseClass instance.
	 */
	union {
		const NMObjBaseClass *klass;
		GTypeInstance g_type_instance;
	};
};

struct _NMObjBaseClass {
	/* NMObjBaseClass is the base class of all NMObjBaseInst implementations.
	 * Note that it is also an abstract super class of GTypeInstance, that means
	 * you may implement a NMObjBaseClass as a subtype of GTypeClass.
	 *
	 * For that to work, you must properly set the GTypeClass instance (and its
	 * GType).
	 *
	 * Note that to implement a NMObjBaseClass that is *not* a GTypeClass, you wouldn't
	 * set the GType. Hence, this field is only useful for type implementations that actually
	 * extend GTypeClass.
	 *
	 * In a way it is wrong that NMObjBaseClass has the GType member, because it is
	 * a base class of GTypeClass and doesn't necessarily use the GType. However,
	 * it is here so that G_TYPE_CHECK_INSTANCE_TYPE() and friends work correctly
	 * on any NMObjectClass. That means, while not necessary, it is convenient that
	 * a NMObjBaseClass has all members of GTypeClass.
	 * Also note that usually you have only one instance of a certain type, so this
	 * wastes just a few bytes for the unneeded GType.
	 */
	union {
		GType g_type;
		GTypeClass g_type_class;
	};
};

/*****************************************************************************/

#endif /* __NM_OBJ_H__ */
