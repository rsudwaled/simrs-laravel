@extends('adminlte::page')

@section('title', 'Edit Role')

@section('content_header')
    <h1>Edit Role</h1>
@stop

@section('content')
    <div class="row">
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
            <x-adminlte-card title="Role {{ $role->name }}" theme="secondary">
                <form action="{{ route('admin.role.store') }}" id="myform" method="post">
                    @csrf
                    <input name="id" value="{{ $role->id }}" hidden />
                    <x-adminlte-input name="name" value="{{ $role->name }}" label="Nama" placeholder="Nama Lengkap"
                        enable-old-support />
                    <x-adminlte-select2 id="role" name="permission[]" label="Role / Jabatan" placeholder="Select a State"
                        enable-old-support multiple>
                        @foreach ($permissions as $permission)
                            <option value="{{ $permission }}"
                                {{ $role->permissions->pluck('name', 'id')->contains($permission) ? 'selected' : '' }}>
                                {{ $permission }}
                            </option>
                        @endforeach
                    </x-adminlte-select2>
                </form>
                <x-adminlte-button form="myform" type="submit" theme="success" label="Simpan" />
                <x-adminlte-button theme="danger" label="Kembali" onclick="window.location='{{ url()->previous() }}'" />
            </x-adminlte-card>
        </div>
    </div>
@stop

@section('plugins.Select2', true)
