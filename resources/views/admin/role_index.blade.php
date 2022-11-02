@extends('adminlte::page')

@section('title', 'Role & Permssion')

@section('content_header')
    <h1>Role & Permission</h1>
@stop

@section('content')
    <div class="row">
        <div class="col-md-3">
            <x-adminlte-small-box title="{{ $roles->total() }}" text="Total Role" theme="success" icon="fas fa-users-cog" />
        </div>
        <div class="col-md-3">
            <x-adminlte-small-box title="{{ $permissions->total() }}" text="Total Permission" theme="success"
                icon="fas fa-user-shield" />
        </div>
        <div class="col-12">
            @if ($errors->any())
                <x-adminlte-alert title="Ops Terjadi Masalah !" theme="danger" dismissable>
                    <ul>
                        @foreach ($errors->all() as $error)
                            <li>{{ $error }}</li>
                        @endforeach
                    </ul>
                </x-adminlte-alert>
            @endif
            <div class="row">
                <div class="col-md-7">
                    <x-adminlte-card title="Tabel Role" theme="secondary" collapsible>
                        <div class="dataTables_wrapper dataTable">
                            <div class="row">
                                <div class="col-md-7">
                                    <x-adminlte-button label="Tambah Role" class="btn-sm" theme="success"
                                        title="Tambah Role" icon="fas fa-plus" data-toggle="modal"
                                        data-target="#modalCreate" />
                                </div>
                                <div class="col-md-5">
                                    <form action="{{ route('admin.role.index') }}" method="get">
                                        <x-adminlte-input name="role" placeholder="Pencarian Role" igroup-size="sm"
                                            value="{{ $request->search }}">
                                            <x-slot name="appendSlot">
                                                <x-adminlte-button type="submit" theme="outline-primary" label="Cari!" />
                                            </x-slot>
                                            <x-slot name="prependSlot">
                                                <div class="input-group-text text-primary">
                                                    <i class="fas fa-search"></i>
                                                </div>
                                            </x-slot>
                                        </x-adminlte-input>
                                    </form>
                                </div>
                            </div>
                            <div class="row">
                                <div class="col-md-12">
                                    @php
                                        $heads = ['Role', 'Permission', 'User', 'Action'];
                                        $config['paging'] = false;
                                        $config['lengthMenu'] = false;
                                        $config['searching'] = false;
                                        $config['info'] = false;
                                        $config['responsive'] = true;
                                    @endphp
                                    <x-adminlte-datatable id="table1" :heads="$heads" :config="$config" hoverable
                                        bordered compressed>
                                        @foreach ($roles as $item)
                                            <tr>
                                                <td>{{ $item->name }}</td>
                                                <td>
                                                    @forelse ($item->permissions as $permission)
                                                        <span class="badge badge-warning">{{ $permission->name }}</span>
                                                    @empty
                                                        -
                                                    @endforelse
                                                </td>
                                                <td>
                                                    {{ $item->users->count() }}
                                                </td>
                                                <td>
                                                    <form action="{{ route('admin.role.destroy', $item) }}" method="POST">
                                                        <x-adminlte-button class="btn-xs" theme="warning" icon="fas fa-edit"
                                                            data-toggle="tooltip" title="Edit {{ $item->name }}"
                                                            onclick="window.location='{{ route('admin.role.edit', $item) }}'" />
                                                        @csrf
                                                        @method('DELETE')
                                                        <x-adminlte-button class="btn-xs" theme="danger"
                                                            icon="fas fa-trash-alt" type="submit"
                                                            onclick="return confirm('Apakah anda akan menghapus Role {{ $item->name }} ?')" />
                                                    </form>
                                                </td>
                                            </tr>
                                        @endforeach
                                    </x-adminlte-datatable>
                                </div>
                            </div>
                            <div class="row">
                                <div class="col-md-6">
                                    <div class="dataTables_info">
                                        Tampil {{ $roles->firstItem() }} sampai {{ $roles->lastItem() }} dari total
                                        {{ $roles->total() }}
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="dataTables_paginate pagination-sm">
                                        {{ $roles->links() }}
                                    </div>
                                </div>
                            </div>
                        </div>
                    </x-adminlte-card>
                </div>
                <div class="col-md-5">
                    <x-adminlte-card title="Tabel Permission" theme="secondary" collapsible>
                        <div class="dataTables_wrapper dataTable">
                            <div class="row">
                                <div class="col-md-6">
                                    <x-adminlte-button label="Tambah Permission" class="btn-sm" theme="success"
                                        title="Tambah Permission" icon="fas fa-plus" data-toggle="modal"
                                        data-target="#modalCreate2" />
                                </div>
                                <div class="col-md-6">
                                    <form action="{{ route('admin.role.index') }}" method="get">
                                        <x-adminlte-input name="search" placeholder="Pencarian Permission" igroup-size="sm"
                                            value="{{ $request->search }}">
                                            <x-slot name="appendSlot">
                                                <x-adminlte-button type="submit" theme="outline-primary" label="Cari!" />
                                            </x-slot>
                                            <x-slot name="prependSlot">
                                                <div class="input-group-text text-primary">
                                                    <i class="fas fa-search"></i>
                                                </div>
                                            </x-slot>
                                        </x-adminlte-input>
                                    </form>
                                </div>
                            </div>
                            <div class="row">
                                <div class="col-md-12">
                                    @php
                                        $heads = ['Permission', 'Role', 'Action'];
                                        $config['paging'] = false;
                                        $config['lengthMenu'] = false;
                                        $config['searching'] = false;
                                        $config['info'] = false;
                                        $config['responsive'] = true;
                                    @endphp
                                    <x-adminlte-datatable id="table2" :heads="$heads" :config="$config" hoverable
                                        bordered compressed>
                                        @foreach ($permissions as $item)
                                            <tr>
                                                <td>
                                                    <span class="badge badge-warning">{{ $item->name }}</span>
                                                </td>
                                                <td>
                                                    {{ $item->roles->count() }}
                                                </td>
                                                <td>
                                                    <form action="{{ route('admin.permission.destroy', $item) }}"
                                                        method="POST">
                                                        <x-adminlte-button class="btn-xs" theme="warning" icon="fas fa-edit"
                                                            data-toggle="tooltip" title="Edit {{ $item->name }}"
                                                            onclick="window.location='{{ route('admin.permission.edit', $item) }}'" />
                                                        @csrf
                                                        @method('DELETE')
                                                        <x-adminlte-button class="btn-xs" theme="danger"
                                                            icon="fas fa-trash-alt" type="submit"
                                                            onclick="return confirm('Apakah anda akan menghapus Permission {{ $item->name }} ?')" />
                                                    </form>
                                                </td>
                                            </tr>
                                        @endforeach
                                    </x-adminlte-datatable>
                                </div>
                            </div>
                            <div class="row">
                                <div class="col-md-6">
                                    <div class="dataTables_info">
                                        Tampil {{ $roles->firstItem() }} sampai {{ $roles->lastItem() }} dari total
                                        {{ $roles->total() }}
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="dataTables_paginate pagination-sm">
                                        {{ $roles->links() }}
                                    </div>
                                </div>
                            </div>
                        </div>
                    </x-adminlte-card>
                </div>
            </div>
        </div>
    </div>
    <x-adminlte-modal id="modalCreate" title="Tambah Role" theme="success" v-centered static-backdrop scrollable>
        <form action="{{ route('admin.role.store') }}" id="myform" method="post">
            @csrf
            <x-adminlte-input name="name" label="Nama" placeholder="Nama Lengkap" enable-old-support required />
            <x-adminlte-select2 id="permission" name="permission[]" label="Permission" placeholder="Select Permission"
                enable-old-support multiple required>
                <x-adminlte-options :options=$select />
            </x-adminlte-select2>
        </form>
        <x-slot name="footerSlot">
            <x-adminlte-button form="myform" class="mr-auto" type="submit" theme="success" label="Simpan" />
            <x-adminlte-button theme="danger" label="Kembali" data-dismiss="modal" />
        </x-slot>
    </x-adminlte-modal>
    <x-adminlte-modal id="modalCreate2" title="Tambah Permission" theme="success" v-centered static-backdrop scrollable>
        <form action="{{ route('admin.permission.store') }}" id="myform2" method="post">
            @csrf
            <x-adminlte-input name="name" label="Nama" placeholder="Nama Lengkap" enable-old-support required />
        </form>
        <x-slot name="footerSlot">
            <x-adminlte-button form="myform2" class="mr-auto" type="submit" theme="success" label="Simpan" />
            <x-adminlte-button theme="danger" label="Kembali" data-dismiss="modal" />
        </x-slot>
    </x-adminlte-modal>
@stop
@section('plugins.Datatables', true)
@section('plugins.Select2', true)
